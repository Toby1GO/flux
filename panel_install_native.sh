#!/bin/bash
set -euo pipefail

export LANG=en_US.UTF-8
export LC_ALL=C

DEFAULT_REPO="bqlpfy/flux-panel"
DEFAULT_VERSION="2.0.7-lite"
REPO="${FLUX_REPO:-$DEFAULT_REPO}"
VERSION="${FLUX_VERSION:-$DEFAULT_VERSION}"
PACKAGE_NAME="flux-panel-native-amd64.tar.gz"
PACKAGE_URL="${FLUX_PACKAGE_URL:-https://github.com/${REPO}/releases/download/${VERSION}/${PACKAGE_NAME}}"
INSTALL_DIR="${FLUX_INSTALL_DIR:-/opt/flux-panel}"
SERVICE_NAME="${FLUX_SERVICE_NAME:-flux-panel}"

check_amd64() {
  case "$(uname -m)" in
    x86_64|amd64)
      ;;
    *)
      echo "错误：当前脚本只支持 amd64/x86_64。"
      exit 1
      ;;
  esac
}

check_tools() {
  for cmd in curl tar systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "错误：缺少命令 $cmd。"
      exit 1
    fi
  done

  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "错误：请使用 root 运行，或安装 sudo。"
    exit 1
  fi
}

generate_random() {
  set +o pipefail
  local value
  value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c32)"
  set -o pipefail
  printf '%s' "$value"
}

read_config() {
  read -p "面板后端端口（默认 6366）: " PANEL_PORT
  PANEL_PORT=${PANEL_PORT:-6366}

  read -p "面板后端公网地址，可留空后续在网站配置里填（例：http://1.2.3.4:${PANEL_PORT}）: " PUBLIC_ADDR
  PUBLIC_ADDR=${PUBLIC_ADDR:-}

  read -p "节点安装脚本地址，可留空使用当前 release 中的 install.sh: " AGENT_INSTALL_URL
  AGENT_INSTALL_URL=${AGENT_INSTALL_URL:-https://github.com/${REPO}/releases/download/${VERSION}/install.sh}

  read -p "节点二进制 release 地址，可留空使用当前 release: " AGENT_RELEASE_URL
  AGENT_RELEASE_URL=${AGENT_RELEASE_URL:-https://github.com/${REPO}/releases/download/${VERSION}}

  JWT_SECRET=${JWT_SECRET:-$(generate_random)}
}

download_package() {
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  if [[ -f "$PACKAGE_NAME" ]]; then
    echo "📦 使用当前目录的 $PACKAGE_NAME"
    cp "$PACKAGE_NAME" "$TMP_DIR/$PACKAGE_NAME"
  else
    echo "🔽 下载 $PACKAGE_URL"
    curl -L "$PACKAGE_URL" -o "$TMP_DIR/$PACKAGE_NAME"
  fi

  mkdir -p "$TMP_DIR/package"
  tar -xzf "$TMP_DIR/$PACKAGE_NAME" -C "$TMP_DIR/package"
}

install_files() {
  $SUDO mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/web"
  $SUDO cp "$TMP_DIR/package/flux-core" "$INSTALL_DIR/flux-core"
  $SUDO chmod +x "$INSTALL_DIR/flux-core"

  $SUDO rm -rf "$INSTALL_DIR/web"
  $SUDO mkdir -p "$INSTALL_DIR/web"
  $SUDO cp -a "$TMP_DIR/package/web/." "$INSTALL_DIR/web/"

  if [[ -f "$TMP_DIR/package/install.sh" ]]; then
    $SUDO cp "$TMP_DIR/package/install.sh" "$INSTALL_DIR/install.sh"
    $SUDO chmod +x "$INSTALL_DIR/install.sh"
  fi

  $SUDO tee "$INSTALL_DIR/.env" >/dev/null <<EOF
FLUX_CORE_ADDR=0.0.0.0:${PANEL_PORT}
FLUX_DB_PATH=${INSTALL_DIR}/data/panel.db
STATIC_DIR=${INSTALL_DIR}/web
JWT_SECRET=${JWT_SECRET}
PUBLIC_ADDR=${PUBLIC_ADDR}
AGENT_INSTALL_URL=${AGENT_INSTALL_URL}
AGENT_RELEASE_URL=${AGENT_RELEASE_URL}
EOF
}

install_service() {
  $SUDO tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<EOF
[Unit]
Description=Flux Panel Native Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/flux-core
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable "$SERVICE_NAME"
  $SUDO systemctl restart "$SERVICE_NAME"
}

print_result() {
  echo ""
  echo "🎉 原生部署完成"
  echo "安装目录: $INSTALL_DIR"
  echo "面板后端地址: http://服务器IP:${PANEL_PORT}"
  echo "默认管理员: admin_user / admin_user"
  echo ""
  echo "查看日志:"
  echo "journalctl -u ${SERVICE_NAME} -f"
  echo ""
  echo "重启服务:"
  echo "systemctl restart ${SERVICE_NAME}"
}

main() {
  check_amd64
  check_tools
  read_config
  download_package
  install_files
  install_service
  print_result
}

main "$@"
