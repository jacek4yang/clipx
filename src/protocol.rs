use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"clipx/1";
pub const CHUNK: usize = 1024 * 1024;
pub const MAX_CONTROL: usize = 64 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_METADATA: usize = 16 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid control message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol limit or invalid message: {0}")]
    Invalid(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;

pub async fn write<T: Serialize>(
    w: &mut (impl AsyncWrite + Unpin + ?Sized),
    value: &T,
) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    if data.len() > MAX_CONTROL {
        return Err(Error::Invalid("control too large"));
    }
    w.write_u32(data.len() as u32).await?;
    w.write_all(&data).await?;
    w.flush().await?;
    Ok(())
}
pub async fn read<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin + ?Sized)) -> Result<T> {
    let len = r.read_u32().await? as usize;
    if len == 0 || len > MAX_CONTROL {
        return Err(Error::Invalid("control length"));
    }
    let mut data = vec![0; len];
    r.read_exact(&mut data).await?;
    Ok(serde_json::from_slice(&data)?)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kind {
    Files,
    Text,
    Image,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub directory: bool,
    pub modified: i64,
    #[serde(default)]
    pub modified_ns: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Offer {
    pub id: uuid::Uuid,
    pub kind: Kind,
    pub count: usize,
    pub total: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Msg {
    Hello {
        version: u32,
        device: String,
        name: String,
        pair: bool,
        chunk: usize,
    },
    Ready {
        version: u32,
        device: String,
        name: String,
        chunk: usize,
    },
    Offer(Offer),
    Entry(Entry),
    Accept {
        workers: usize,
    },
    File {
        index: usize,
    },
    Resume {
        offset: u64,
    },
    Chunk {
        offset: u64,
        logical: usize,
        encoded: usize,
        compressed: bool,
        hash: String,
    },
    Ack,
    Busy,
    FileDone {
        hash: String,
    },
    WorkerDone,
    Finish,
    Paths {
        paths: Vec<String>,
    },
    Complete {
        paths: Vec<String>,
    },
    Error {
        message: String,
    },
}
pub fn check_version(version: u32, chunk: usize) -> Result<()> {
    if version != 1 || chunk != CHUNK {
        return Err(Error::Invalid("incompatible protocol/chunk version"));
    }
    Ok(())
}
pub fn encode(data: &[u8], mode: &str) -> Result<(Vec<u8>, bool)> {
    if data.len() > CHUNK {
        return Err(Error::Invalid("chunk too large"));
    }
    if mode == "off" {
        return Ok((data.to_vec(), false));
    }
    // Sampling avoids full compression of already compressed/random payloads, independent of suffix.
    if mode == "auto" && data.len() > 4096 {
        let sample = &data[..4096];
        if zstd::bulk::compress(sample, 1)?.len() >= sample.len() * 95 / 100 {
            return Ok((data.to_vec(), false));
        }
    }
    let encoded = zstd::bulk::compress(data, 1)?;
    if encoded.len() >= data.len() {
        Ok((data.to_vec(), false))
    } else {
        Ok((encoded, true))
    }
}
pub fn decode(data: &[u8], logical: usize, compressed: bool, hash: &str) -> Result<Vec<u8>> {
    if logical == 0 || logical > CHUNK || data.len() > CHUNK {
        return Err(Error::Invalid("chunk length"));
    }
    let decoded = if compressed {
        let mut decoder = zstd::bulk::Decompressor::new()?;
        decoder.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(20))?;
        decoder.decompress(data, logical)?
    } else {
        data.to_vec()
    };
    if decoded.len() != logical || blake3::hash(&decoded).to_hex().as_str() != hash {
        return Err(Error::Invalid("chunk integrity mismatch"));
    }
    Ok(decoded)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn framing() {
        let (mut a, mut b) = tokio::io::duplex(MAX_CONTROL * 2);
        write(&mut a, &Msg::Ack).await.unwrap();
        assert!(matches!(read::<Msg>(&mut b).await.unwrap(), Msg::Ack));
        a.write_u32(MAX_CONTROL as u32 + 1).await.unwrap();
        assert!(read::<Msg>(&mut b).await.is_err());
    }
    #[test]
    fn integrity_and_limits() {
        let data = vec![42; CHUNK];
        let hash = blake3::hash(&data).to_hex().to_string();
        for mode in ["auto", "off", "zstd"] {
            let (encoded, compressed) = encode(&data, mode).unwrap();
            assert_eq!(
                decode(&encoded, data.len(), compressed, &hash).unwrap(),
                data
            );
            assert!(decode(&encoded, data.len(), compressed, "bad").is_err());
            assert!(decode(&encoded, CHUNK + 1, compressed, &hash).is_err());
        }
        assert!(check_version(2, CHUNK).is_err());
        assert!(check_version(1, 1).is_err());
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::*;
    #[tokio::test]
    async fn truncated_and_invalid_frames() {
        for payload in [
            vec![],
            b"not-json".to_vec(),
            vec![0xff; 100],
            b"{\"type\":\"unknown\"}".to_vec(),
        ] {
            let (mut a, mut b) = tokio::io::duplex(1000);
            a.write_u32(payload.len() as u32).await.unwrap();
            a.write_all(&payload).await.unwrap();
            a.shutdown().await.unwrap();
            assert!(read::<Msg>(&mut b).await.is_err());
        }
        let (mut a, mut b) = tokio::io::duplex(1000);
        a.write_u32(100).await.unwrap();
        a.write_all(b"short").await.unwrap();
        a.shutdown().await.unwrap();
        assert!(read::<Msg>(&mut b).await.is_err());
    }
    proptest::proptest! {
        #[test]
        fn arbitrary_control_json_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY,0..4096)) {
            let _=serde_json::from_slice::<Msg>(&data);
        }
    }
}
