#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ShadowRecon v2.0 — Installer
# Tested on: Kali Linux, Ubuntu 22.04+, Debian 12+, macOS (brew python3)
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗"
echo "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝"
echo "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║     "
echo "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║     "
echo "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝"
echo -e "  R E C O N N A I S S A N C E   F R A M E W O R K   v2.0${NC}"
echo ""

# ── Python check ──────────────────────────────────────────────────────────────
PY=$(command -v python3 2>/dev/null || true)
[ -z "$PY" ] && fail "Python 3 not found. Install it: sudo apt install python3"
PYVER=$("$PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python $PYVER found at $PY"

# Require 3.10+
PYMAJ=$("$PY" -c "import sys; print(sys.version_info.major)")
PYMIN=$("$PY" -c "import sys; print(sys.version_info.minor)")
if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 10 ]; }; then
  fail "Python 3.10+ required. Found $PYVER"
fi

# ── pip packages ──────────────────────────────────────────────────────────────
info "Installing Python dependencies ..."

PACKAGES=(
  "requests"
  "dnspython"
  "python-whois"
  "rich"
  "tldextract"
  "ipwhois"
  "beautifulsoup4"
  "mmh3"
)

for pkg in "${PACKAGES[@]}"; do
  info "  Installing $pkg ..."
  "$PY" -m pip install "$pkg" --break-system-packages -q 2>&1 | tail -1 || \
  "$PY" -m pip install "$pkg" -q 2>&1 | tail -1 || \
  warn "  Could not install $pkg — install manually: pip install $pkg"
done
ok "Python packages installed"

# ── Optional: mmh3 (pure-python fallback exists if missing) ───────────────────
"$PY" -c "import mmh3" 2>/dev/null && ok "mmh3 available (favicon hash module ready)" || \
  warn "mmh3 not installed — favicon_hash module will use pure-Python fallback (slightly slower)"

# ── openssl check (for deprecated protocol tests) ─────────────────────────────
if command -v openssl &>/dev/null; then
  SSLVER=$(openssl version 2>/dev/null | head -1)
  ok "openssl found: $SSLVER"
else
  warn "openssl not in PATH — deprecated TLS protocol tests will be skipped"
fi

# ── Verify import chain ───────────────────────────────────────────────────────
info "Verifying framework imports ..."
cd "$(dirname "$0")"
"$PY" -c "
import sys
sys.path.insert(0, '.')
from core.engine   import Engine
from core.registry import MODULE_REGISTRY
from core.reporter import Reporter
from core.output   import OutputManager
print(f'  Modules registered: {len(MODULE_REGISTRY)}')
" && ok "Import check passed" || fail "Import check failed — check error above"

# ── Create output dir ─────────────────────────────────────────────────────────
mkdir -p output
ok "Output directory: $(pwd)/output"

# ── Wrapper script ────────────────────────────────────────────────────────────
WRAPPER="$(dirname "$0")/sr"
cat > "$WRAPPER" <<WRAP
#!/usr/bin/env bash
cd "$(dirname "\$0")"
exec python3 shadowrecon.py "\$@"
WRAP
chmod +x "$WRAPPER"
ok "Wrapper script created: sr  (run with: ./sr -d example.com)"

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Usage:${NC}"
echo "    python3 shadowrecon.py -d example.com"
echo "    python3 shadowrecon.py -d example.com --modules all --threads 20"
echo "    python3 shadowrecon.py -d example.com --passive-only"
echo "    python3 shadowrecon.py -d example.com --github-token TOKEN --shodan-key KEY"
echo "    python3 shadowrecon.py --list-modules"
echo ""
echo -e "  ${BOLD}Output:${NC} output/<domain>_<timestamp>/{report.html, report.json, report.txt}"
echo ""
