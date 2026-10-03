# clipx 中文使用指南

用一个 Rust 可执行文件，在 Windows 11、Linux Mint 和无桌面的 Linux 之间
主动推送剪贴板、文件或目录。适合 Tailscale / Headscale 内网，直接输入 IP
或主机名，不需要广播发现、云服务、账号或图形界面。

这是首个候选版本，尚不等于已经通过所有实体电脑和网络环境的长期验收。
完整的能力边界、协议和安全模型见 [README](README.md) 与 [SECURITY](SECURITY.md)。

## 第一次使用：双方核对指纹

每台电脑执行：

```sh
clipx fingerprint
```

通过可信渠道核对两台电脑显示的指纹。接收电脑信任发送电脑：

```sh
clipx peer trust 发送电脑的64位指纹
clipx recv --bind 100.64.0.6
```

发送电脑信任接收电脑，并设一个好记的别名：

```sh
clipx peer trust 接收电脑的64位指纹 --host 100.64.0.6
clipx peer add lab 100.64.0.6
clipx send lab
```

把例子里的 IP 和指纹替换成自己的。不要直接复制占位文字。
之后通常只需让接收端一直运行 `clipx recv`，发送端复制内容后执行
`clipx send lab`。双向发送时，在另一方向也配好信任。
更改信任后重启接收进程。身份更换会报错，不会悄悄接受新证书。

## 常用命令

```sh
clipx send lab --path project
clipx send lab --path report.pdf --path photo.png
clipx send lab --text "你好"
clipx recv --headless
clipx send lab --transport tcp
clipx send lab --compression off
clipx send lab --resume 之前打印的传输UUID
clipx cleanup
clipx doctor
```

- 自动读取优先级：复制的文件/目录 → 图片 → 文字
- 文件/目录进入系统的下载目录，不覆盖同名项，会加 `(1)`、`(2)` 后缀
- 文字/图片进入接收端剪贴板；无桌面或写剪贴板失败时保存为下载目录中的文件
- 普通文件分块处理，目录不需要预先制作整份压缩包
- QUIC 优先，建立认证会话慢时自动尝试 TCP/TLS；中断后按已验证的数据续传
- 默认 TCP 和 UDP 都用 45817，防火墙和 tailnet ACL 需要允许它们
- 推荐绑定 Tailscale IP；默认 IPv4 通配地址也会暴露在局域网上，但仍需身份认证
- Linux X11 要保持接收进程运行以持有剪贴板；Wayland 依赖桌面支持 data-control
- 不默认监控剪贴板，也不会自动传播每一次复制，避免悄悄同步密码等内容

文件大小用 64 位表示。剪贴板图片/文字仍受系统与内存限制，不承诺无限容量。
断线期间会保留续传数据；默认 `cleanup` 清理超过 7 天且未被活动进程锁定的状态。

## 构建与发布

项目固定 Rust 工具链和 Cargo.lock。CI 在 Windows 和 Linux 上执行格式检查、
Clippy、单元/网络测试、真实剪贴板测试、杀掉接收进程后的自动恢复测试，
通过后才允许发布打包文件和 SHA-256 校验和。

```sh
cargo build --locked --release
```

发布包中的程序无需 Node/Python/Java。仓库里的 Python 文件仅供开发测试和打包。
