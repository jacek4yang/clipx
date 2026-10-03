# clipx：复制，发送，核对

单个 Rust 二进制，面向 Windows 11 / Linux Mint x64。没有账号、配置文件、持久密钥、信任列表、后台服务或开机启动。

## 安装

到 [Releases](https://github.com/jacek4yang/clipx/releases) 下载对应系统的包，核对 SHA256SUMS.txt，解压后只保留二进制也能运行。
- Linux x64 优先 musl 静态版，将 clipx 放入 ~/.local/bin，并确保该目录在 PATH 中。
- Windows x64 将 clipx.exe 放入自己选定的 PATH 目录。无需额外 MSVC 运行库；未签名，系统可能提示正常安全检查。
- 不同系统/CPU 需要对应二进制，不存在真正适用于所有电脑的同一个文件。

## 最简单的用法

接收电脑：
```sh
clipx recv
```
发送电脑先复制文件、图片或文字，然后：
```sh
clipx send 对方IP
```
两边显示同一串一次性指纹，人工核对整行相同，再在两端分别输入 y。每次连接，包括断线重连，都生成新的指纹，不记住任何设备。默认回车或输入 n 拒绝。

如果信任当前网络，可以分别省略某一端的确认：
```sh
clipx recv --yes
clipx send --yes 对方IP
```
--yes 只影响当前这一端、当前进程，不会替另一端确认，也不保存设置。
recv --yes 会在运行期间自动接受传入请求，只建议在可信网络、受控的 Tailscale ACL 下使用。两端都 --yes 仍然加密，但没有人工身份核验，不能防止主动冒充/中间人。

## 其他常用操作

```sh
clipx recv --bind 你的TailscaleIP
clipx recv --headless
clipx send 对方IP --path 文件或目录
clipx send 对方IP --text "你好"
clipx send 对方IP --transport tcp
clipx cleanup
```

默认端口 UDP/TCP 45817，程序不自动更改防火墙。--stdin 支持管道文字；默认从控制终端读取确认，无终端时应明确选择 --yes。--json 输出到 stdout，确认/警告仍在 stderr。

## 保持纯净

发送端不写配置、密钥、缓存或剪贴板临时文件。接收端只在下载目录创建最终文件，以及传输期间必要的 .clipx-part-UUID 断点目录；成功确认后删除断点目录。它不含密钥、指纹或信任列表。
中断后保持源文件不变，重复原命令即可匹配断点；两端进程重启也能续传，仍重新核对指纹。接收端校验已有块，双方比较前缀哈希，不一致时从该文件开头重新发送。
clipx cleanup 清理超过七天且不活跃的断点；--days 可调整。没有定时清理或常驻安装。

为了不保留历史，成功完成后的记录也删除。极端崩溃若丢失完成确认，重新发送可能得到带序号的副本，但绝不覆盖旧文件。已提示 Verified 后若仅清理确认失败，不需要为该警告重发。

## 能力与边界

QUIC 优先、TCP/TLS 回退，TLS 1.3。一次性指纹绑定双方临时证书及当前 TLS 会话，RC2 与 RC1 协议不兼容，请两端一起升级。
文件/目录按 1 MiB 块流式传输，支持 zstd、块及完整文件 BLAKE3 校验、断点续传。目录不先生成完整压缩包。
剪贴板文字/图片需要内存；超大数据建议作为文件发送。Linux X11 支持剪贴板所有权，接收进程需保持运行；Wayland 依赖合成器 data-control 协议，不能保证任意 GNOME Wayland。无剪贴板时在 Downloads 保存文字/PNG。
不支持符号链接、特殊文件或无效 Unicode 文件名；可移植文件名会做必要映射。不会导入远端权限、执行位、ACL 或执行收到的文件。

这是候选版。三平台构建及自动化测试覆盖不等于所有真实硬件均验证，也不承诺超过 LocalSend。详细边界见 [英文说明](README.md)、[验证记录](docs/VALIDATION.md) 和 [安全说明](SECURITY.md)。
