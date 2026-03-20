#!/bin/bash
# Setup ProjectDiscovery tools and other security tool dependencies for Overwatch V2

set -e

GOBIN="${GOPATH:-$HOME/go}/bin"
export PATH="$PATH:$GOBIN"

echo "=== Overwatch V2 — Security Tools Setup ==="
echo "GOBIN: $GOBIN"

# Check for Go
if ! command -v go &>/dev/null; then
    echo "ERROR: Go is not installed. Install from https://go.dev/dl/ first."
    exit 1
fi

echo ""
echo "--- Installing ProjectDiscovery tools ---"

install_pd_tool() {
    local pkg="$1"
    local bin="$2"
    if command -v "$bin" &>/dev/null; then
        echo "  ✓ $bin already installed ($(command -v "$bin"))"
    else
        echo "  Installing $pkg..."
        go install "$pkg@latest"
        echo "  ✓ $bin installed"
    fi
}

install_pd_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"    "nuclei"
install_pd_tool "github.com/projectdiscovery/httpx/cmd/httpx"          "httpx"
install_pd_tool "github.com/projectdiscovery/katana/cmd/katana"        "katana"
install_pd_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu"       "naabu"
install_pd_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
install_pd_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client" "interactsh-client"

echo ""
echo "--- Checking system tools ---"

check_tool() {
    local bin="$1"
    if command -v "$bin" &>/dev/null; then
        echo "  ✓ $bin found at $(command -v "$bin")"
    else
        echo "  ✗ $bin NOT FOUND — install with your package manager"
    fi
}

check_tool nmap
check_tool docker
check_tool python3

echo ""
echo "--- Updating Nuclei templates ---"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent && echo "  ✓ Nuclei templates updated"
fi

echo ""
echo "--- Checking Python dependencies ---"
pip install -r requirements.txt 2>/dev/null || pip install poetry && poetry install

echo ""
echo "=== Setup complete ==="
echo "Run 'docker compose up -d' to start infrastructure (PostgreSQL, Redis, MinIO)"
echo "Then: uvicorn src.overwatch.api.main:app --reload"
