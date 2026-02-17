# xsint

`xsint` is a command-line OSINT tool that runs multiple modules against one target.

## Install

```bash
git clone https://github.com/memorypudding/xsint.git
cd xsint
./install.sh
```

`install.sh`:
- picks a compatible Python (3.10 to 3.13)
- creates `~/.local/share/xsint/.venv`
- installs `xsint` and dependencies
- installs wrapper commands in `~/.local/bin`: `xsint`, `ghunt`, `gitfive`

## Command usage

```text
usage: xsint [-h] [--modules [TYPE]] [--auth [ARGS ...]]
             [--proxy URL] [--set-proxy URL]
             [target]

positional arguments:
  target                Target to scan

optional arguments:
  -h, --help            show this help message and exit
  --modules [TYPE], -m [TYPE]
                        List modules for an input type (e.g. --modules email)
  --auth [ARGS ...]
                        Configure credentials for a module (e.g. --auth hibp
                        KEY, --auth ghunt, --auth haxalot). Run --auth to
                        show auth status.
  --proxy URL           Proxy URL (e.g. socks5://127.0.0.1:9050)
  --set-proxy URL       Save a default proxy URL
```

## Common examples

```bash
# Detect target type automatically
xsint user@example.com
xsint +14155551234
xsint 8.8.8.8

# Set target type explicitly
xsint email:user@example.com
xsint phone:+14155551234
xsint user:johndoe
xsint ip:8.8.8.8
xsint "name:John Doe"
xsint "addr:Tokyo, Japan"
xsint hash:5f4dcc3b

# Run through a proxy
xsint --proxy socks5://127.0.0.1:9050 user@example.com
```

## Modules output

`xsint -m` prints modules, whether each one is active or locked, and which input types each module supports.

```text
module          status  types
ghunt_lookup    locked  EMAIL|PHONE
gitfive_module  locked  EMAIL|USERNAME
haxalot_module  locked  EMAIL|IP|PHONE|USERNAME
hibp            active  EMAIL|HASH|PHONE|USERNAME
intelx          locked  EMAIL|PHONE|USERNAME
ip_basic        active  IP
nineghz         active  EMAIL|HASH|ID|IP|NAME|PASSPORT|PHONE|SSN|USERNAME
osm             active  ADDRESS
phone_basic     active  PHONE
```

Use `xsint -m <type>` to filter by input type.

## Module authentication

Use `--auth` for API keys, login/setup flows, and auth status:

```bash
# View auth status
xsint --auth

# API key based modules
xsint --auth hibp YOUR_HIBP_KEY
xsint --auth intelx YOUR_INTELX_KEY
xsint --auth 9ghz YOUR_9GHZ_KEY

# Interactive module setup
xsint --auth ghunt
xsint --auth gitfive
xsint --auth haxalot
```

## Notes

- GHunt and GitFive require Python 3.10+.
- If `~/.local/bin` is not in your `PATH`, add it in your shell profile.
