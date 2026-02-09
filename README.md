<h1 align="center">
  <a href="https://github.com/memorypudding/xsint"><img src="preview.png" width="700" title="xsint preview"></a>
</h1>

[![platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20OSX-success.svg)](https://github.com/memorypudding/xsint) [![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/memorypudding/xsint)

**xsint** is a modern OSINT toolkit that queries [multiple reconnaissance services](#apis) from a single command. Supports emails, phone numbers, usernames, IPs, hashes, names, and more.

----

## :book: Table of Contents

- [Features](#tangerine-features)
  - [APIs](#apis)
- [Installation](#tangerine-installation)
- [Usage](#tangerine-usage)
- [Usage Examples](#tangerine-usage-examples)
- [Modules](#tangerine-modules)
- [API Keys & Module Setup](#tangerine-api-keys--module-setup)
- [Thanks & Credits](#tangerine-thanks--credits)

----

## :tangerine: Features

* :mag_right: Auto-detection of input type (email, IP, phone)
* :label: Explicit type prefixes for advanced queries (`user:`, `hash:`, `ssn:`, `passport:`, etc.)
* :package: Simple install via `pip` or run directly with `python3 -m xsint`
* :globe_with_meridians: DNS & MX record lookups
* :detective: Google account discovery via GHunt
* :octopus: GitHub profile & email resolution via GitFive
* :fire: Breach data from multiple sources (9Ghz, HIBP, IntelX, Haxalot)
* :telephone_receiver: Phone number parsing (country, carrier, line type, timezone)
* :earth_africa: Address geocoding via OpenStreetMap
* :key: Configurable API keys with persistent storage
* :shield: Proxy support (SOCKS5, HTTP)
* :zap: Async module execution for speed

---

### :package: Install from source

```bash
git clone https://github.com/memorypudding/xsint.git && cd xsint && pip install .
```

-----

### APIs

| Service | Functions | Status |
|-|-|-|
| [9Ghz](https://9ghz.com/) | Breach count, breach names & dates | :white_check_mark: :key: |
| [HaveIBeenPwned](https://haveibeenpwned.com/) | Breach names, breach dates | :white_check_mark: :key: |
| [IntelX](https://intelx.io/) | Breaches, leaks, pastes, documents | :white_check_mark: :key: |
| [GHunt](https://github.com/mxrch/GHunt) | Gaia ID, profile, services, maps, calendar | :white_check_mark: |
| [GitFive](https://github.com/mxrch/GitFive) | Email resolution, GitHub profile, SSH keys | :white_check_mark: |
| Haxalot (Telegram bot) | Breaches, passwords, PII | :white_check_mark: :key: |
| MX / DNS Lookup | Mail server, provider detection | :white_check_mark: |
| Phone Basic | Country, carrier, line type, timezone | :white_check_mark: |
| IP Basic | Version, private/public | :white_check_mark: |
| OSM Geocoding | Address, coordinates, location type | :white_check_mark: |

*:key: - API key required*

-----

## :tangerine: Installation

#### No install (run directly)

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
pip install -r requirements.txt
python3 -m xsint
```

#### pip (from source)

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
pip install .
```

After installing, the `xsint` command is available globally.

-----

## :tangerine: Usage

```bash
usage: xsint [-h] [--list] [--list-modules [TYPE]] [--set-key ARGS [ARGS ...]] [--proxy URL] [--set-proxy URL] [target]

XSINT - OSINT Switchblade

positional arguments:
  target                Target to scan

options:
  -h, --help            show this help message and exit
  --list, -l            List supported input types and API key status
  --list-modules [TYPE]
                        List modules for an input type (e.g. --list-modules email)
  --set-key ARGS [ARGS ...]
                        Set an API key (e.g. 'hibp YOUR_KEY') or setup a module (e.g. 'haxalot')
  --proxy URL           Proxy URL (e.g. socks5://127.0.0.1:9050)
  --set-proxy URL       Save a default proxy URL
```

-----

## :tangerine: Usage Examples

###### Query a single email

```bash
$ xsint user@example.com
```

###### Query with explicit type prefix

```bash
$ xsint email:user@example.com
$ xsint phone:+14155551234
$ xsint user:johndoe
$ xsint ip:8.8.8.8
$ xsint "name:John Doe"
$ xsint "addr:Tokyo, Japan"
$ xsint hash:5f4dcc3b
$ xsint id:1234567890
```

###### Auto-detection (emails, IPs, phone numbers)

```bash
$ xsint user@example.com
$ xsint 8.8.8.8
$ xsint +14155551234
```

###### Use a proxy

```bash
$ xsint --proxy socks5://127.0.0.1:9050 user@example.com
```

###### Save a default proxy

```bash
$ xsint --set-proxy socks5://127.0.0.1:9050
```

-----

## :tangerine: Modules

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

-----

## :tangerine: API Keys & Module Setup

Some modules require API keys. Set them with:

```bash
$ xsint --set-key hibp YOUR_HIBP_KEY
$ xsint --set-key 9ghz YOUR_9GHZ_KEY
```

The Haxalot module requires a Telegram login:

```bash
$ xsint --set-key haxalot
```

[GHunt](https://github.com/mxrch/GHunt) and [GitFive](https://github.com/mxrch/GitFive) require their own setup before they can be used with xsint. Follow their respective installation guides:

```bash
# GHunt setup
$ ghunt login

# GitFive setup
$ gitfive login
```

Check key status:

```bash
$ xsint --list
```

-----

## :tangerine: Thanks & Credits

* [mxrch](https://github.com/mxrch) for [GHunt](https://github.com/mxrch/GHunt) & [GitFive](https://github.com/mxrch/GitFive)
* [IntelX](https://intelx.io) for their API
* [HaveIBeenPwned](https://haveibeenpwned.com/) by Troy Hunt
* [9Ghz](https://9ghz.com/) for breach data
* [Anthropic](https://anthropic.com/) for Claude AI
* [opencode](https://github.com/opencode-ai/opencode) for development tooling
