#!/usr/bin/env bash
# Beautiful, automated deployment for Open-Source Dockerized SOC
# Based on repository installation guidelines
# Requires: root privileges

set -euo pipefail

# -------- Configuration --------
BASE_DIR="/opt/SOC"
NETWORK="SOC_NET"
WAZUH_REPO="https://github.com/wazuh/wazuh-docker.git"
WAZUH_BRANCH="v4.12.0"
MISP_REPO="https://github.com/MISP/misp-docker.git"
SHUFFLE_REPO="https://github.com/Shuffle/Shuffle"

# -------- Colors & Formatting --------
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"

print_info()    { echo -e "${BLUE}[INFO]${RESET}    $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${RESET}    $1"; }
print_error()   { echo -e "${RED}[ERROR]${RESET}   $1"; exit 1; }

# -------- Prerequisite Checks --------
[ "$EUID" -eq 0 ] || print_error "This script must be run as root or with sudo."
for cmd in git docker docker-compose apt-get curl gpg; do
    command -v "$cmd" >/dev/null 2>&1 || print_error "${cmd} is required but not installed."
done
print_success "All prerequisites are present."

# -------- Prepare Base Directory --------
print_info "Creating base directory at ${BASE_DIR}..."
mkdir -p "$BASE_DIR"
print_success "Base directory ready."

# -------- Docker Network --------
print_info "Creating Docker network ${NETWORK}..."
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK"
print_success "Network ${NETWORK} is ready."

# -------- Wazuh Setup --------
print_info "Setting up Wazuh (XDR/SIEM)..."
WAZUH_DIR="$BASE_DIR/wazuh-docker"
if [ -d "$WAZUH_DIR/.git" ]; then
    git -C "$WAZUH_DIR" fetch --all && git -C "$WAZUH_DIR" reset --hard "origin/${WAZUH_BRANCH}"
else
    git clone --branch "$WAZUH_BRANCH" "$WAZUH_REPO" "$WAZUH_DIR"
fi
cd "$WAZUH_DIR/single-node"
print_info "Generating indexer certificates..."
docker-compose -f generate-indexer-certs.yml run --rm generator
print_info "Starting Wazuh services..."
docker-compose up -d
print_success "Wazuh deployed at https://127.0.0.1:9443 (admin/SecretPassword)"

# -------- MISP + TheHive Setup --------
print_info "Setting up MISP (Threat Intelligence) & TheHive (Incident Response)..."
MISP_DIR="$BASE_DIR/misp-docker"
if [ -d "$MISP_DIR/.git" ]; then
    git -C "$MISP_DIR" pull
else
    git clone "$MISP_REPO" "$MISP_DIR"
fi
cd "$MISP_DIR"
cp template.env .env
print_info "(Optional) Customize .env if needed..."
docker-compose up -d
print_success "MISP at https://127.0.0.1:8443 (admin@admin.test/admin) and TheHive at http://127.0.0.1:9000 (admin/secret)"

# -------- Shuffle Setup --------
print_info "Setting up Shuffle (Automation)..."
SHUFFLE_DIR="$BASE_DIR/Shuffle"
if [ -d "$SHUFFLE_DIR/.git" ]; then
    git -C "$SHUFFLE_DIR" pull
else
    git clone "$SHUFFLE_REPO" "$SHUFFLE_DIR"
fi
cd "$SHUFFLE_DIR"
print_info "Preparing OpenSearch DB prerequisites..."
DB_DIR="$SHUFFLE_DIR/shuffle-database"
mkdir -p "$DB_DIR"
id -u opensearch &>/dev/null || sudo useradd opensearch
chown -R 1000:1000 "$DB_DIR"
print_info "Disabling swap and tuning vm.max_map_count..."
swapoff -a\ nsysctl -w vm.max_map_count=262144
print_info "Starting Shuffle containers..."
docker-compose up -d
print_success "Shuffle available at https://127.0.0.1:3443"

# -------- Caddy Setup --------
print_info "Installing and configuring Caddy..."
print_info "Adding Caddy repository and key..."
apt-get update\ napt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy.list
apt-get update && apt-get install -y caddy

print_info "Writing Caddyfile..."
CAT_FILE="/etc/caddy/Caddyfile"
cat > "$CAT_FILE" <<EOF
{
    local_certs
}

wazuh.dashboard {
    reverse_proxy https://127.0.0.1:9443 {
        transport http { tls_insecure_skip_verify }
    }
}

misp.local {
    reverse_proxy https://127.0.0.1:8443 {
        transport http { tls_insecure_skip_verify }
    }
}

thehive.local {
    reverse_proxy http://127.0.0.1:9000
}

shuffle.local {
    reverse_proxy https://127.0.0.1:3443 {
        transport http { tls_insecure_skip_verify }
    }
}
EOF

print_info "Updating /etc/hosts entries..."
HOSTS_LINE="127.0.0.1 misp.local wazuh.dashboard thehive.local shuffle.local"
grep -q "${HOSTS_LINE}" /etc/hosts || echo "$HOSTS_LINE" >> /etc/hosts

print_info "Reloading Caddy service..."
systemctl reload caddy
print_success "Caddy is configured. Access via custom domains."

# -------- Final Status --------
print_info "Fetching all container statuses..."
docker-compose -f "$WAZUH_DIR/single-node/docker-compose.yml" ps || true
docker-compose -f "$MISP_DIR/docker-compose.yml" ps || true
docker-compose -f "$SHUFFLE_DIR/docker-compose.yml" ps || true

print_success "Full SOC stack deployed successfully!"
print_info "Use 'docker-compose logs -f' in each folder for detailed logs."
