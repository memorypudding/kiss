```
▌  ▗
▌▗▘▄ ▞▀▘▞▀▘
▛▚ ▐ ▝▀▖▝▀▖
▘ ▘▀▘▀▀ ▀▀
```

**Keeping Identity Search Simple.** — a minimal OSINT tool.

## Install

```bash
git clone https://github.com/memorypudding/kiss.git
cd kiss
pip install -r requirements.txt
pip install .
```

## Usage

```bash
kiss email:user@example.com
kiss phone:+14155551234
kiss user:johndoe
kiss ip:8.8.8.8
kiss "name:John Doe"
kiss "addr:Tokyo, Japan"
kiss hash:5f4dcc3b
kiss id:1234567890
kiss ssn:123-45-6789
kiss passport:AB1234567
```

Auto-detection works for emails, IPs, and phone numbers:

```bash
kiss user@example.com
kiss 8.8.8.8
kiss +14155551234
```

## API Keys

Some modules require API keys. Set them with:

```bash
kiss --set-key hibp YOUR_HIBP_KEY
kiss --set-key 9ghz YOUR_9GHZ_KEY
```

Or use environment variables:

```bash
export KISS_HIBP_API_KEY=your_key
export KISS_9GHZ_API_KEY=your_key
```

Check key status:

```bash
kiss --list
```

## Modules

List all modules:

```bash
kiss --list-modules
kiss --list-modules email
```

Modules are self-describing `.py` files in `kiss/modules/`. Each declares an `INFO` dict:

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
| `github` | username | none |
| `osm` | address | none |

## Proxy

```bash
# One-time
kiss --proxy socks5://127.0.0.1:9050 email:user@example.com

# Save default
kiss --set-proxy socks5://127.0.0.1:9050

# Clear
kiss --set-proxy off
```

Supports HTTP, SOCKS4, and SOCKS5. SSL verification is disabled when proxying.

## Writing a Module

Create a `.py` file in `kiss/modules/`:

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
