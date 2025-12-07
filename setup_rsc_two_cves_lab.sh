#!/usr/bin/env bash
set -e

###############################################################################
# 双靶场漏洞环境一键部署脚本（最终修正版）
#
#  http://服务器IP:3000 → React2Shell（CVE-2025-55182）
#  http://服务器IP:3001 → Next.js 16.0.6（CVE-2025-66478）
#
#  所有 git clone 走 hxorz.cn 代理
###############################################################################

LAB_DIR="next_rsc_two_cves_lab"

echo "[*] 创建实验目录: ${LAB_DIR}"
mkdir -p "${LAB_DIR}"
cd "${LAB_DIR}"

###############################################################################
# 1. 克隆两个仓库
###############################################################################

if [ ! -d "CVE-2025-55182-msanft" ]; then
  echo "[*] 克隆 CVE-2025-55182 PoC..."
  git clone https://hxorz.cn/gh/msanft/CVE-2025-55182.git CVE-2025-55182-msanft
fi

if [ ! -d "Next.js-RSC-RCE-Scanner-CVE-2025-66478" ]; then
  echo "[*] 克隆 Next.js 扫描器..."
  git clone https://hxorz.cn/gh/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478.git
fi

if [ ! -d "React2Shell-src" ]; then
  echo "[*] 克隆 React2Shell 源码..."
  git clone https://hxorz.cn/gh/subzer0x0/React2Shell.git React2Shell-src
fi

###############################################################################
# 2. 生成 Next.js 16.0.6 项目（漏洞版本）
###############################################################################

if [ ! -d "nextjs-66478" ]; then
  echo "[*] 生成 Next.js 16.0.6 项目..."
  npx create-next-app@16.0.6 nextjs-66478 \
    --use-npm \
    --ts=false \
    --tailwind=false \
    --eslint=false \
    --src-dir=false \
    --app \
    --import-alias="@/*"
fi

###############################################################################
# 3. 写 Dockerfile
###############################################################################

cat > nextjs-66478/Dockerfile << 'EOF'
FROM node:22-alpine

WORKDIR /app

# 只拷 package.json，避免通配符和重定向错误
COPY package.json ./

RUN npm install

# 再拷全部项目
COPY . .

ENV HOST=0.0.0.0
EXPOSE 3000

CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0"]
EOF

###############################################################################
# 4. 写 docker-compose（两个端口：3000 / 3001）
###############################################################################

cat > docker-compose.yml << 'EOF'
version: "3.9"

services:
  react2shell:
    image: arulkumarv/react2shell:v1
    container_name: react2shell-cve-2025-55182
    ports:
      - "3000:3000"
    restart: unless-stopped

  nextjs-66478:
    build:
      context: ./nextjs-66478
      dockerfile: Dockerfile
    container_name: nextjs-cve-2025-66478
    ports:
      - "3001:3000"
    environment:
      - HOST=0.0.0.0
    restart: unless-stopped
EOF

###############################################################################
# 5. 构建并启动两个容器
###############################################################################

echo "[*] 构建并启动两个漏洞容器..."
docker compose down || true
docker compose up -d --build

###############################################################################
# 6. 构建 Go 扫描器
###############################################################################

if command -v go >/dev/null 2>&1; then
  echo "[*] 构建 Next.js 扫描器..."
  cd Next.js-RSC-RCE-Scanner-CVE-2025-66478
  go build -o ../nextjs-rce-scanner
  cd ..
else
  echo "[!] 未检测到 go，跳过 scanner 构建"
fi

###############################################################################
# 7. 创建 urls.txt（给 scanner 用）
###############################################################################

echo "http://127.0.0.1:3001" > urls.txt

###############################################################################
# 8. 可选：为 Python PoC 建 venv
###############################################################################

if command -v python3 >/dev/null 2>&1; then
  cd CVE-2025-55182-msanft
  python3 -m venv venv || true
  if [ -d "venv" ]; then
    . venv/bin/activate
    pip install --upgrade pip >/dev/null 2>&1 || true
    pip install requests >/dev/null 2>&1 || true
    deactivate
  fi
  cd ..
fi

###############################################################################
# 9. 输出最终访问信息
###############################################################################

SERVER_IP=$(hostname -I | awk '{print $1}')

cat <<EOM

======================================================================

部署完成。

React2Shell（CVE-2025-55182）：
  本机访问:   curl http://127.0.0.1:3000
  远程访问:   http://${SERVER_IP}:3000

Next.js 16.0.6（CVE-2025-66478）：
  本机访问:   curl http://127.0.0.1:3001
  远程访问:   http://${SERVER_IP}:3001

当前容器状态：
----------------------------------------------------------------------
$(docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "react2shell|nextjs-cve-2025-66478")
----------------------------------------------------------------------

停止环境：
  docker compose down

======================================================================
仅限本地 / 授权环境测试使用。
======================================================================

EOM

