# React Server Components (RSC) 漏洞检测与靶场工具集
# RSC-VulnLab

![Language](https://img.shields.io/badge/README-English-blue)
[Click here for English Version](./english-README.md)

---

本项目提供了针对 React Server Components (RSC) 相关漏洞的检测工具和一键部署靶场环境，主要涵盖 CVE-2025-55182 (React2Shell) 和 CVE-2025-66478 (Next.js RSC RCE) 两个高危漏洞。

## 目录结构

```
.
├── install_nuclei.sh                      # Nuclei 扫描器官方安装脚本
├── setup_rsc_two_cves_lab.sh             # 双靶场漏洞环境一键部署脚本
├── next_rsc_two_cves_lab/                # 靶场环境目录
│   ├── docker-compose.yml                # Docker Compose 配置文件
│   ├── nextjs-66478/                     # Next.js 16.0.6 漏洞环境
│   ├── nextjs-rce-scanner                # Next.js RSC RCE 扫描器二进制文件
│   └── urls.txt                          # 目标 URL 列表
├── nmap-nse/                             # Nmap NSE 检测脚本
│   ├── nextjs-rsc-cve-2025-66478-detect.nse
│   └── react2shell-cve-2025-55182-detect.nse
└── nuclei-custom/                        # Nuclei 自定义模板
    ├── nextjs-cve-2025-66478-rce-3001.yaml
    ├── nextjs-cve-2025-66478-rce-body-id.yaml
    ├── react2shell-cve-2025-55182-rce-body-id.yaml
    └── react2shell-cve-2025-55182-rce-safe-check.yaml
```

## 漏洞概述

### CVE-2025-55182 (React2Shell)
- 影响版本：受影响的 React/Next.js 应用
- 漏洞类型：通过 RSC 反序列化实现远程代码执行
- 靶场端口：3000

### CVE-2025-66478 (Next.js RSC RCE)
- 影响版本：Next.js 16.0.6 及其他易受攻击版本
- 漏洞类型：通过 NEXT_REDIRECT digest 注入实现远程代码执行
- 靶场端口：3001

## 快速开始

### 1. 部署靶场环境

运行一键部署脚本，将自动构建并启动两个漏洞靶场：

```bash
bash setup_rsc_two_cves_lab.sh
```

部署完成后，可通过以下地址访问：

- React2Shell (CVE-2025-55182): `http://服务器IP:3000`
- Next.js 16.0.6 (CVE-2025-66478): `http://服务器IP:3001`

停止靶场环境：

```bash
cd next_rsc_two_cves_lab
docker compose down
```

### 2. 安装 Nuclei 扫描器

使用官方安装脚本安装 Nuclei v3.6.0：

```bash
bash install_nuclei.sh
```

安装完成后验证：

```bash
nuclei -version
```

## 检测工具使用

### Nuclei 模板扫描

使用自定义 Nuclei 模板进行漏洞检测：

```bash
# 检测 React2Shell (CVE-2025-55182)
nuclei -t nuclei-custom/react2shell-cve-2025-55182-rce-safe-check.yaml -u http://目标IP:3000

# 检测 Next.js RSC RCE (CVE-2025-66478)
nuclei -t nuclei-custom/nextjs-cve-2025-66478-rce-3001.yaml -u http://目标IP:3001

# 批量扫描
nuclei -t nuclei-custom/ -l urls.txt
```

### Nmap NSE 脚本检测

使用 Nmap 脚本引擎进行端口扫描和漏洞检测：

```bash
# 检测 React2Shell (端口 3000)
nmap --script=nmap-nse/react2shell-cve-2025-55182-detect.nse -p 3000 目标IP

# 检测 Next.js RSC RCE (端口 3001)
nmap --script=nmap-nse/nextjs-rsc-cve-2025-66478-detect.nse -p 3001 目标IP

# 同时检测两个漏洞
nmap --script=nmap-nse/*.nse -p 3000,3001 目标IP
```

### Go 扫描器使用

如果已构建 Go 扫描器，可直接运行：

```bash
cd next_rsc_two_cves_lab
./nextjs-rce-scanner -l urls.txt
```

## 检测原理

所有检测工具均通过以下方式验证漏洞：

1. 发送精心构造的 RSC multipart/form-data 请求
2. 触发服务端执行安全命令（如 `id`）
3. 检查响应中的 `digest` 字段是否包含命令执行结果
4. 提取并展示命令输出（如 `uid=0(root)`）

检测过程仅执行读取系统信息的命令，不会对目标系统造成破坏。

## 工具说明

### install_nuclei.sh
- 从 GitHub 官方仓库下载 Nuclei v3.6.0
- 支持代理环境下载
- 自动安装并配置到 `/usr/local/bin/nuclei`

### setup_rsc_two_cves_lab.sh
- 自动克隆相关 PoC 仓库（通过 hxorz.cn 代理）
- 生成 Next.js 16.0.6 漏洞项目
- 构建并启动两个 Docker 容器
- 可选构建 Go 扫描器和 Python PoC 环境

### Nuclei 模板特性
- 支持精确的正则表达式匹配
- 自动提取命令执行输出
- 分级检测（安全检查 / Body ID 检查 / 端口特定检查）

### Nmap NSE 脚本特性
- 专注于 digest 字段检测
- 不执行破坏性命令
- 详细的漏洞确认输出
- 支持自定义端口规则

## 安全警告

本项目仅供授权安全测试和学习研究使用。使用前请确保：

1. 仅在受控的本地环境或已获授权的测试环境中部署靶场
2. 不得将检测工具用于未经授权的系统
3. 遵守当地法律法规和网络安全相关规定

## 参考资源

- CVE-2025-55182: https://github.com/msanft/CVE-2025-55182
- React2Shell: https://github.com/subzer0x0/React2Shell
- Next.js RSC RCE Scanner: https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478
- Nuclei: https://github.com/projectdiscovery/nuclei

## 技术栈

- Docker & Docker Compose
- Node.js 22 (Alpine)
- Next.js 16.0.6
- Nuclei v3.6.0
- Nmap NSE (Lua)
- Go (扫描器)
- Python 3 (PoC 环境)

## 许可证

本项目中的检测脚本和工具遵循各自的开源许可证：
- Nmap NSE 脚本：与 Nmap 相同许可证
- Nuclei 模板：与 Nuclei 相同许可证
- 其他工具：请参考各原始项目的许可证

## 作者

hxorz

## 免责声明

本项目仅用于安全研究和教育目的。使用者应自行承担使用本项目所产生的一切法律责任。项目作者不对任何滥用行为负责。
