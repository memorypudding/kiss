#!/usr/bin/env bash
set -euo pipefail

# xsint installer
# Creates a venv, installs all deps (including ghunt + gitfive),
# and drops a global `xsint` command into ~/.local/bin.

INSTALL_DIR="${XSINT_INSTALL_DIR:-$HOME/.local/share/xsint}"
BIN_DIR="${XSINT_BIN_DIR:-$HOME/.local/bin}"
MIN_MINOR=10
MAX_MINOR=13

red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
cyan()   { printf '\033[1;36m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

# --- Find a compatible Python (3.10–3.13) ---
find_python() {
    for cmd in python3.10 python3.11 python3.12 python3.13 python3; do
        local p
        p=$(command -v "$cmd" 2>/dev/null) || continue
        local ver
        ver=$("$p" -c "import sys; print(f'{sys.version_info.minor}')" 2>/dev/null) || continue
        if [ "$ver" -ge "$MIN_MINOR" ] && [ "$ver" -le "$MAX_MINOR" ]; then
            echo "$p"
            return
        fi
    done
}

PYTHON=$(find_python)
if [ -z "$PYTHON" ]; then
    red "[!] No Python 3.${MIN_MINOR}–3.${MAX_MINOR} found."
    echo ""
    echo "  Detected interpreters:"
    for cmd in python3 python3.9 python3.10 python3.11 python3.12 python3.13 python3.14; do
        p=$(command -v "$cmd" 2>/dev/null) || continue
        full=$("$p" --version 2>&1) || continue
        echo "    $p: $full"
    done
    echo ""
    echo "  Install a compatible version:"
    cyan "    brew install python@3.13"
    exit 1
fi

PY_VER=$("$PYTHON" --version 2>&1)
dim "Using: $PYTHON ($PY_VER)"
echo ""

# --- Resolve source directory (where this script lives) ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Create install directory and venv ---
mkdir -p "$INSTALL_DIR"

VENV_DIR="$INSTALL_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    cyan "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
    echo ""
fi

# --- Upgrade pip ---
"$VENV_PYTHON" -m pip install --upgrade pip --quiet

# --- Copy project files ---
cyan "Copying xsint into $INSTALL_DIR..."
rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='.git' \
    --exclude='.claude' --exclude='*.pyc' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"
echo ""

# --- Install xsint + deps ---
cyan "Installing xsint and dependencies..."
"$VENV_PYTHON" -m pip install -e "$INSTALL_DIR" --quiet
echo ""

# --- Install ghunt + gitfive ---
cyan "Installing ghunt + gitfive..."
"$VENV_PYTHON" -m pip install ghunt gitfive --quiet
echo ""

# --- Install ghunt CLI via pipx (for `ghunt login`) ---
if command -v pipx &>/dev/null; then
    cyan "Installing ghunt CLI (via pipx)..."
    pipx install ghunt --python "$PYTHON" --force 2>/dev/null || true
    echo ""
else
    dim "pipx not found — skipping ghunt CLI install."
    dim "Install with: brew install pipx"
    echo ""
fi

# --- Create global wrapper script ---
mkdir -p "$BIN_DIR"
WRAPPER="$BIN_DIR/xsint"

cat > "$WRAPPER" << WRAPPER_EOF
#!/usr/bin/env bash
exec "$VENV_PYTHON" -m xsint "\$@"
WRAPPER_EOF
chmod +x "$WRAPPER"

green "Installed xsint to: $WRAPPER"
echo ""

# --- Check if BIN_DIR is on PATH ---
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "  Add this to your shell profile (~/.zshrc or ~/.bashrc):"
    cyan "    export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
fi

# --- Prompt to log in ---
for tool in ghunt gitfive; do
    read -rp "Log in to $tool now? (y/n): " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        if command -v "$tool" &>/dev/null; then
            "$tool" login
        else
            "$VENV_DIR/bin/$tool" login 2>/dev/null || \
                dim "$tool login not available as a CLI command."
        fi
    fi
done

echo ""
green "Setup complete!"
echo "  Run: xsint <target>"
