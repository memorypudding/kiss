```

                 "             m
 m   m   mmm   mmm    m mm   mm#mm
  #m#   #   "    #    #"  #    #      By: Hollow
  m#m    """m    #    #   #    #      v0.1.0
 m" "m  "mmm"  mm#mm  #   #    "mm
```

**XSINT** — a minimal OSINT tool.

## Installation

### pip (system-wide)

```bash
pip install xsint
```

### pip (from source)

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
pip install .
```

### pipx (isolated)

```bash
pipx install xsint
```

### From source (development)

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
pip install -e .
```

After installing, the `xsint` command is available globally:

```bash
xsint --help
```

### Uninstall

```bash
pip uninstall xsint
```

## Usage

```bash
xsint email:user@example.com
xsint phone:+14155551234
xsint user:johndoe
xsint ip:8.8.8.8
xsint "name:John Doe"
xsint "addr:Tokyo, Japan"
xsint hash:5f4dcc3b
xsint id:1234567890
xsint ssn:123-45-6789
xsint passport:AB1234567
```

Auto-detection works for emails, IPs, and phone numbers:

```bash
xsint user@example.com
xsint 8.8.8.8
xsint +14155551234
```

## API Keys

Some modules require API keys. Set them with:

```bash
xsint --set-key hibp YOUR_HIBP_KEY
xsint --set-key 9ghz YOUR_9GHZ_KEY
```

Or use environment variables:

```bash
export XSINT_HIBP_API_KEY=your_key
export XSINT_9GHZ_API_KEY=your_key
```

Check key status:

```bash
xsint --list
```

## Modules

List all modules:

```bash
xsint --list-modules
xsint --list-modules email
```

Modules are self-describing `.py` files in `xsint/modules/`. Each declares an `INFO` dict:

```python
INFO = {
    "free": ["hash"],                        # works without a key
    "paid": ["email", "username", "phone"],  # requires api key
    "api_key": "hibp",
    "returns": ["breaches", "breach names", "breach dates"],
}

async def run(session, target):
    ...
```

| Module | Types | Key |
|--------|-------|-----|
| `hibp` | hash (free), email/username/phone (key) | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| `nineghz` | email, username, phone, ip, hash, name, id, ssn, passport | optional ([9ghz.com](https://9ghz.com)) |
| `email_basic` | email | none |
| `phone_basic` | phone | none |
| `ip_basic` | ip | none |
| `osm` | address | none |

## Proxy

```bash
# One-time
xsint --proxy socks5://127.0.0.1:9050 email:user@example.com

# Save default
xsint --set-proxy socks5://127.0.0.1:9050

# Clear
xsint --set-proxy off
```

Supports HTTP, SOCKS4, and SOCKS5. SSL verification is disabled when proxying.

## Writing a Module

Create a `.py` file in `xsint/modules/`:

```python
INFO = {
    "free": ["email"],
    "returns": ["some data"],
}

async def run(session, target):
    # session is an aiohttp.ClientSession
    # target is the cleaned input string
    # return (status, [results])
    #   status: 0 = success, 1 = failure
    #   results: list of {"label", "value", "source", "risk"}
    return 0, [
        {"label": "Example", "value": "data", "source": "MyModule", "risk": "low"}
    ]
```

That's it. No registration, no base classes. The engine discovers it automatically.
