<p align="center">
  <a href="https://github.com/memorypudding/xsint">
    <img src="preview.png" width="700" alt="xsint preview">
  </a>
</p>
<p align="center">A modern OSINT toolkit.</p>
<p align="center">
  <a href="https://github.com/memorypudding/xsint"><img alt="platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20OSX-success.svg" /></a>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue.svg" /></a>
  <a href="https://github.com/memorypudding/xsint"><img alt="Version" src="https://img.shields.io/badge/version-0.1.0-orange.svg" /></a>
  <a href="https://github.com/memorypudding/xsint"><img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg" /></a>
</p>

> **Prototype — work in progress.** Expect breaking changes and incomplete features.

**xsint** queries [multiple reconnaissance services](#apis) from a single command. Supports emails, phone numbers, usernames, IPs, hashes, names, and more.

---

### Installation

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
./install.sh
```

This will auto-detect a compatible Python (3.10–3.13), create a venv, install all dependencies (including GHunt + GitFive), and add a global `xsint` command to `~/.local/bin`.

Or install locally for development:

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
python3.13 -m xsint --setup

source .venv/bin/activate
xsint <target>
```

### Features

- Auto-detection of input type (email, IP, phone)
- Explicit type prefixes for advanced queries (`user:`, `hash:`, `ssn:`, `passport:`, etc.)
- DNS & MX record lookups
- Google account discovery via GHunt
- GitHub profile & email resolution via GitFive
- Breach data from multiple sources (9Ghz, HIBP, IntelX, Haxalot)
- Phone number parsing (country, carrier, line type, timezone)
- Address geocoding via OpenStreetMap
- Configurable API keys with persistent storage
- Proxy support (SOCKS5, HTTP)
- Async module execution

### APIs

| Service | Functions | Status |
|-|-|-|
| [9Ghz](https://9ghz.com/) | Breach count, breach names & dates | Available (key required) |
| [HaveIBeenPwned](https://haveibeenpwned.com/) | Breach names, breach dates | Available (key required) |
| [IntelX](https://intelx.io/) | Breaches, leaks, pastes, documents | Available (key required) |
| [GHunt](https://github.com/mxrch/GHunt) | Gaia ID, profile, services, maps, calendar | Available (pipx, Python 3.10+) |
| [GitFive](https://github.com/mxrch/GitFive) | Email resolution, GitHub profile, SSH keys | Available (pipx, Python 3.10+) |
| Haxalot (Telegram bot) | Breaches, passwords, PII | Available (key required) |
| MX / DNS Lookup | Mail server, provider detection | Available |
| Phone Basic | Country, carrier, line type, timezone | Available |
| IP Basic | Version, private/public | Available |
| OSM Geocoding | Address, coordinates, location type | Available |

### Usage

```
usage: xsint [-h] [--list] [--list-modules [TYPE]] [--set-key ARGS [ARGS ...]] [--setup] [--proxy URL] [--set-proxy URL] [target]

positional arguments:
  target                Target to scan

options:
  -h, --help            show this help message and exit
  --list, -l            List supported input types and API key status
  --list-modules [TYPE] List modules for an input type (e.g. --list-modules email)
  --set-key ARGS        Set an API key (e.g. 'hibp YOUR_KEY') or setup a module (e.g. 'haxalot')
  --setup               Install external tools (GHunt, GitFive) via pipx
  --proxy URL           Proxy URL (e.g. socks5://127.0.0.1:9050)
  --set-proxy URL       Save a default proxy URL
```

##### Examples

```bash
# Auto-detection
xsint user@example.com
xsint 8.8.8.8
xsint +14155551234

# Explicit type prefix
xsint email:user@example.com
xsint phone:+14155551234
xsint user:johndoe
xsint ip:8.8.8.8
xsint "name:John Doe"
xsint "addr:Tokyo, Japan"
xsint hash:5f4dcc3b
xsint id:1234567890

# With proxy
xsint --proxy socks5://127.0.0.1:9050 user@example.com
```

### Modules

```
EMAIL          6/7 modules
  + email_basic        mx records
  + ghunt_lookup       gaia_id, profile, services, maps, calendar
  + gitfive_module     email, profile_info, ssh_keys
  + haxalot_module     breaches, passwords, pii
  x hibp               breaches, breach names, breach dates (requires hibp key)
  + intelx             breaches, leaks, pastes, documents
  + nineghz            breaches

PHONE          5/6 modules
  + ghunt_lookup       gaia_id, profile, services, maps, calendar
  + haxalot_module     breaches, passwords, pii
  x hibp               breaches, breach names, breach dates (requires hibp key)
  + intelx             breaches, leaks, pastes, documents
  + nineghz            breaches
  + phone_basic        formats, country, carrier, line type, timezone

USERNAME       4/5 modules
  + gitfive_module     email, profile_info, ssh_keys
  + haxalot_module     breaches, passwords, pii
  x hibp               breaches, breach names, breach dates (requires hibp key)
  + intelx             breaches, leaks, pastes, documents
  + nineghz            breaches

IP             3 modules
  + haxalot_module     breaches, passwords, pii
  + ip_basic           version, private/public
  + nineghz            breaches

HASH           2 modules
  + hibp               breaches, breach names, breach dates
  + nineghz            breaches

NAME           1 module  —  nineghz
ID             1 module  —  nineghz
SSN            1 module  —  nineghz
PASSPORT       1 module  —  nineghz
ADDRESS        1 module  —  osm
```

### API Keys & Module Setup

```bash
# Set API keys
xsint --set-key hibp YOUR_HIBP_KEY
xsint --set-key 9ghz YOUR_9GHZ_KEY

# Haxalot (Telegram login)
xsint --set-key haxalot

# Check key status
xsint --list
```

[GHunt](https://github.com/mxrch/GHunt) and [GitFive](https://github.com/mxrch/GitFive) require **Python 3.10–3.13** and are installed automatically by `./install.sh`. To log in after installation:

```bash
ghunt login
gitfive login
```

### Thanks & Credits

- [mxrch](https://github.com/mxrch) for [GHunt](https://github.com/mxrch/GHunt) & [GitFive](https://github.com/mxrch/GitFive)
- [IntelX](https://intelx.io) for their API
- [HaveIBeenPwned](https://haveibeenpwned.com/) by Troy Hunt
- [9Ghz](https://9ghz.com/) for breach data
- [Anthropic](https://anthropic.com/) for Claude AI
- [opencode](https://github.com/anomalyco/opencode) for development tooling
