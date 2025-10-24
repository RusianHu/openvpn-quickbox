# ovpnx.sh

[![GNU Bash](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=fff)](https://www.gnu.org/software/bash/) [![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?logo=ubuntu&logoColor=fff)](https://ubuntu.com/download) [![License](https://img.shields.io/badge/License-Apache--2.0-black)](LICENSE)

一键 OpenVPN 安装与管理脚本，围绕 Ubuntu 22.04/24.04 的默认 systemd 布局设计，旨在一条命令完成安装、证书生命周期、服务管理与彻底卸载。

## 功能速览
- 一键安装流程：探测系统、安装依赖、初始化 Easy-RSA PKI、生成 `dh.pem`、写入服务端配置与 systemd 服务。
- TLS/密码套件预调优：默认启用 `data-ciphers`、`tls-groups prime256v1`、`tls-crypt`，确保 OpenVPN 2.6+ 对齐；固定 `group nogroup` 避免 Ubuntu 24.04 坑。
- 客户端生命周期：菜单式创建、列出、吊销与清理客户端证书，输出内联 `.ovpn`。
- 网络与防火墙：自动开启 IPv4 转发、配置 UFW NAT 规则，回滚时保留/移除自有标记。
- 全量备份：所有 PKI/客户端文件集中在 `WORKDIR`（默认 `/opt/ovpnx`），包含自动备份与保留逻辑。

## 快速开始

1. `git clone https://github.com/RusianHu/openvpn-quickbox.git && cd openvpn-quickbox`
2. `chmod +x ovpnx.sh`
3. `sudo ./ovpnx.sh`
4. 安装向导结束后在菜单中生成客户端配置文件。

直接运行单文件：

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

1) 安装 / 初始化（向导）
2) 生成客户端 .ovpn（内联证书）
3) 列出证书 (有效/吊销)
4) 吊销客户端证书
5) 清理已吊销证书的文件
6) 查看服务状态与日志
7) 重启服务
8) 卸载（保留工作区与备份）
9) 彻底清除（含工作区与包）
0) 退出
```

## 设计细节
- 系统与 OpenVPN 版本自动探测，保持 Ubuntu 22.04/24.04 兼容与提示。
- 证书逻辑基于 Easy-RSA，支持 ECC CA/服务端证书，同时仍生成 Diffie-Hellman 参数。
- 支持 `sudo OVPNX_WORKDIR=/path/to/workdir ./ovpnx.sh` 自定义工作区；卸载可保留或清空资产。

## 许可证
本项目基于 [Apache License 2.0](LICENSE) 发布。
