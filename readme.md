# ovpnx.sh 一键openVPN部署脚本

[![License](https://img.shields.io/badge/License-Apache--2.0-black)](LICENSE)

一键 OpenVPN 安装与管理脚本，基于 Ubuntu 22.04/24.04 ，一条命令完成安装、证书生命周期、服务管理与彻底卸载。

## 功能速览
- 一键安装流程：探测系统、检查 OpenVPN 版本、安装依赖、初始化 Easy-RSA PKI（ECC），生成 `dh.pem`，并写入 server.conf 与 systemd 服务。
- TLS/密码套件预调优并自修复：默认启用 `data-ciphers`、`tls-groups prime256v1`、`tls-crypt`、`group nogroup`；启动时自动补齐/更新 `tls-cipher` 列表，提示重启生效。
- 客户端全生命周期：创建/列出/吊销/清理吊销文件，支持对缺失或被吊销的客户端自动重签；生成内联 `.ovpn` 并支持公网 IP/域名自动探测。
- 运维友好：菜单头部实时展示服务状态，提供状态/日志查看、重启与安全的“停止服务”。
- 网络与防火墙：自动开启 IPv4 转发、配置 UFW NAT（带标记便于卸载），并对 `WORKDIR`/系统配置变更自动备份以便回滚。

## 快速开始
直接运行：

```bash
curl -fsSLo ovpnx.sh https://raw.githubusercontent.com/RusianHu/openvpn-quickbox/main/ovpnx.sh
chmod +x ovpnx.sh
sudo ./ovpnx.sh
```

## 界面演示

```text
root@box:~# ./ovpnx.sh
OpenVPN 管理脚本 ovpnx.sh
系统: Ubuntu 24.04 | OpenVPN 2.6.10
工作区: /opt/ovpnx
服务端配置: /etc/openvpn/server/server.conf
服务名: openvpn-server@server.service
服务状态: 运行中

1) 安装 / 初始化（向导）
2) 生成客户端 .ovpn（内联证书）
3) 列出证书 (有效/吊销)
4) 吊销客户端证书
5) 清理已吊销证书的文件
6) 查看服务状态与日志
7) 重启服务
8) 停止服务
9) 彻底清除（含工作区与包）
0) 退出
```

## 设计细节
- 系统与 OpenVPN 版本自动探测，保持 Ubuntu 22.04/24.04 兼容并在旧版上给出警告。
- 证书逻辑基于 Easy-RSA，默认 ECC CA/服务端证书，同时生成 DH 参数并输出 `tls-groups` 配置。
- 再次运行脚本会校验已有 server.conf 的 `tls-cipher`，缺失/不一致时自动修复并提示重启。
- 生成客户端支持自动检测公网 IP/域名，吊销后可一键清理已吊销客户端的文件与归档。
- 对 `WORKDIR`、UFW、sysctl、`server.conf` 等敏感文件变更前自动备份；可通过 `sudo OVPNX_WORKDIR=/path/to/workdir ./ovpnx.sh` 自定义工作区。

## 许可证
本项目基于 [Apache License 2.0](LICENSE) 发布。
