#!/usr/bin/env python3
"""
XSINT - Open Source Intelligence Tool

This file provides backward compatibility with the original single-file version.
For new installations, use the modular version: python -m xsint

Usage:
    python xsint-test.py
    OR
    python -m xsint
"""

import sys
import re
import hashlib
import threading
import subprocess
import importlib
import ipaddress
import queue
import time
import curses
import random
import math
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
# API keys should be set via environment variables or ~/.xsint/config.json
# See .env.example for available environment variables
API_KEYS = {
    "HIBP": "",  # Set XSINT_HIBP_API_KEY environment variable
    "PREDICTA": "",
    "IPSTACK": "",
    "VERIPHONE": "",
    "SHERLOCKEYE": "",
    "EMAIL_VALIDATOR": ""
}

# Try to load from environment
import os
for key in API_KEYS:
    env_var = f"XSINT_{key}_KEY" if key != "HIBP" else "XSINT_HIBP_API_KEY"
    if os.environ.get(env_var):
        API_KEYS[key] = os.environ[env_var]
    # Also try legacy env var names
    if os.environ.get(f"{key}_API_KEY"):
        API_KEYS[key] = os.environ[f"{key}_API_KEY"]

# --- DEPENDENCY BOOTSTRAPPER ---
def bootstrap_deps():
    required = {
        "requests": "requests",
        "phonenumbers": "phonenumbers",
        "dns": "dnspython",
        "email_validator": "email_validator"
    }
    for module, pkg in required.items():
        try:
            importlib.import_module(module)
        except ImportError:
            print(f"Installing {pkg}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {pkg}: {e}", file=sys.stderr)

bootstrap_deps()

# --- IMPORTS ---
import requests
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier
from email_validator import validate_email, EmailNotValidError

import logging
logger = logging.getLogger(__name__)

# --- ENGINE ---
class ServiceScanner:
    def __init__(self, session, printer_callback):
        self.session = session
        self.print = printer_callback
        self.headers = {
            "User-Agent": "XSINT-Tool/3.0",
            "Accept": "application/json"
        }
        # HIBP Rate Limiting Controls
        self.hibp_lock = threading.Lock()
        self.last_hibp_req = 0.0

    def check_google(self, email):
        return None

    def check_gravatar(self, email):
        try:
            email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
            url = f"https://en.gravatar.com/{email_hash}.json"
            r = self.session.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                entry = data['entry'][0]
                return {"service": "Gravatar", "status": "Found", "details": f"User: {entry.get('preferredUsername')}", "color": "green"}
        except requests.Timeout:
            logger.debug("Gravatar request timed out")
        except requests.ConnectionError:
            logger.debug("Failed to connect to Gravatar")
        except (ValueError, KeyError, IndexError) as e:
            logger.debug(f"Failed to parse Gravatar response: {e}")
        except requests.RequestException as e:
            logger.debug(f"Gravatar request failed: {e}")
        return None

    def check_twitter(self, email):
        try:
            url = f"https://api.twitter.com/i/users/email_available.json?email={email}"
            r = self.session.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200 and r.json().get("valid") == False:
                return {"service": "Twitter", "status": "Found", "details": "Email is registered", "color": "green"}
        except requests.Timeout:
            logger.debug("Twitter request timed out")
        except requests.ConnectionError:
            logger.debug("Failed to connect to Twitter")
        except (ValueError, KeyError) as e:
            logger.debug(f"Failed to parse Twitter response: {e}")
        except requests.RequestException as e:
            logger.debug(f"Twitter request failed: {e}")
        return None

    def _request_hibp(self, endpoint):
        """
        Thread-safe, rate-limited helper for HIBP API.
        Enforces strict 1.6s spacing between requests globally.
        """
        if not API_KEYS["HIBP"]:
            return None

        url = f"https://haveibeenpwned.com/api/v3/{endpoint}"
        headers = {
            "hibp-api-key": API_KEYS["HIBP"],
            "User-Agent": "XSINT-Tool",
            "Content-Type": "application/json"
        }

        with self.hibp_lock:
            # 1. Throttle: Ensure at least 1.6 seconds have passed since last request
            now = time.time()
            elapsed = now - self.last_hibp_req
            if elapsed < 1.6:
                time.sleep(1.6 - elapsed)

            try:
                # 2. Execute Request
                r = self.session.get(url, headers=headers, timeout=10)
                self.last_hibp_req = time.time()

                # 3. Handle Rate Limit (429) gracefully
                if r.status_code == 429:
                    try:
                        retry_after = float(r.headers.get("retry-after", 2)) + 1.0
                        time.sleep(retry_after)
                        r = self.session.get(url, headers=headers, timeout=10)
                        self.last_hibp_req = time.time()
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Failed to parse retry-after header: {e}")

                return r
            except requests.Timeout:
                logger.warning(f"HIBP request timed out for {endpoint}")
                return None
            except requests.ConnectionError as e:
                logger.error(f"HIBP connection error: {e}")
                return None
            except requests.RequestException as e:
                logger.error(f"HIBP request error: {e}")
                return None

    def check_hibp_breach(self, target):
        """Checks HIBP BreachedAccount API v3"""
        try:
            query = target.strip()
            if re.match(r"^\+?[0-9\-\s]+$", query) and "@" not in query:
                 query = re.sub(r"\D", "", query)

            encoded_query = urllib.parse.quote(query)
            r = self._request_hibp(f"breachedaccount/{encoded_query}?truncateResponse=false")

            if r is None:
                if not API_KEYS["HIBP"]:
                    return {"service": "HIBP Breach", "status": "Skipped", "details": "API Key Missing", "color": "yellow"}
                return {"service": "HIBP Breach", "status": "Error", "details": "Connection Failed", "color": "red"}

            if r.status_code == 200:
                breaches = r.json()
                count = len(breaches)
                top_3 = ", ".join([b['Name'] for b in breaches[:3]])
                if count > 3: top_3 += f" and {count-3} more"
                return {"service": "HIBP Breach", "status": "Found", "details": f"PWNED! {count} breaches: {top_3}", "color": "red"}
            elif r.status_code == 404:
                return {"service": "HIBP Breach", "status": "Clean", "details": "No breaches found", "color": "green"}
            elif r.status_code == 401:
                return {"service": "HIBP Breach", "status": "Error", "details": "Unauthorized (Invalid Key)", "color": "red"}
            else:
                return {"service": "HIBP Breach", "status": "Error", "details": f"HTTP {r.status_code}", "color": "red"}
        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse HIBP breach response: {e}")
            return {"service": "HIBP Breach", "status": "Error", "details": "Invalid response", "color": "red"}
        except Exception as e:
            logger.exception(f"Unexpected error in HIBP breach check: {e}")
            return {"service": "HIBP Breach", "status": "Error", "details": "Unknown Error", "color": "red"}

    def check_hibp_pastes(self, target):
        """Checks HIBP PasteAccount API v3"""
        if "@" not in target: return None
        try:
            encoded_query = urllib.parse.quote(target.strip())
            r = self._request_hibp(f"pasteaccount/{encoded_query}")

            if r is None: return {"service": "HIBP Paste", "status": "Skipped", "details": "Check Key/Conn", "color": "yellow"}

            if r.status_code == 200:
                pastes = r.json()
                count = len(pastes)
                sources = ", ".join([p.get('Source', 'Unknown') for p in pastes[:3]])
                return {"service": "HIBP Paste", "status": "Found", "details": f"Found in {count} pastes ({sources})", "color": "red"}
            elif r.status_code == 404:
                return {"service": "HIBP Paste", "status": "Clean", "details": "No pastes found", "color": "green"}
            else:
                return {"service": "HIBP Paste", "status": "Error", "details": f"HTTP {r.status_code}", "color": "red"}
        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse HIBP paste response: {e}")
            return {"service": "HIBP Paste", "status": "Error", "details": "Invalid response", "color": "red"}
        except Exception as e:
            logger.exception(f"Unexpected error in HIBP paste check: {e}")
            return {"service": "HIBP Paste", "status": "Error", "details": str(e), "color": "red"}

    def check_hibp_stealer_logs(self, email):
        return None

    def check_hibp_domain(self, domain):
        """Checks HIBP Domain Search"""
        try:
            encoded_query = urllib.parse.quote(domain.strip())
            r = self._request_hibp(f"breacheddomain/{encoded_query}")

            if r is None: return None

            if r.status_code == 200:
                data = r.json()
                total_aliases = len(data)
                return {"service": "HIBP Domain", "status": "Found", "details": f"Breaches found for {total_aliases} aliases", "color": "red"}
            elif r.status_code == 404:
                return {"service": "HIBP Domain", "status": "Clean", "details": "No breaches for this domain", "color": "green"}
            else:
                return {"service": "HIBP Domain", "status": "Error", "details": f"HTTP {r.status_code}", "color": "red"}
        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse HIBP domain response: {e}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error in HIBP domain check: {e}")
            return None

    def run_all_scans(self, target, progress_callback=None):
        checks = [self.check_google, self.check_gravatar, self.check_twitter]
        results = []
        total = len(checks)
        completed = 0

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(func, target) for func in checks]
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception as e:
                    logger.error(f"Email check failed: {e}")
                completed += 1
                if progress_callback:
                    progress_callback(completed / total)
        return results

class XSINT:
    def __init__(self, output_callback):
        self.session = requests.Session()
        self.printer = output_callback
        self.scanner = ServiceScanner(self.session, self.printer)

    def detect_input_type(self, text):
        if not text: return None
        try:
            ipaddress.IPv4Address(text)
            return "IP"
        except ipaddress.AddressValueError:
            pass

        try:
            ipaddress.IPv6Address(text)
            return "IP"
        except ipaddress.AddressValueError:
            pass

        try:
            validate_email(text, check_deliverability=False)
            return "EMAIL"
        except EmailNotValidError:
            pass

        try:
            p = phonenumbers.parse(text, None)
            if phonenumbers.is_valid_number(p): return "PHONE"
        except phonenumbers.NumberParseException:
            pass

        if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", text): return "BSSID"
        if "." in text and " " not in text and not text.startswith(("@", "+")): return "DOMAIN"
        if " " in text and all(part.isalpha() for part in text.split()): return "NAME"
        if re.match(r"^\d+\s+\w+", text): return "ADDRESS"
        return "USERNAME"

    def _render_table(self, title, rows):
        """Renders a formatted ASCII table to the printer"""
        width = 64 # Inner width
        self.printer(f"\n {title} ", "white")

        # Top Border
        self.printer("┌" + "─"*18 + "┬" + "─"*(width-19) + "┐", "white")

        for row in rows:
            label = row.get("label", "Unknown")[:16]
            val = row.get("val", "")[:width-21]
            color = row.get("color", "white")

            # Row Content
            line = f"│ {label:<16} │ {val:<{width-21}} │"
            self.printer(line, color)

        # Bottom Border
        self.printer("└" + "─"*18 + "┴" + "─"*(width-19) + "┘", "white")

    def scan_ip(self, ip, progress_cb):
        progress_cb(0.1)
        data = []
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                info = r.json()
                progress_cb(0.4)
                for k, v in info.items():
                    if k in ['ip', 'hostname', 'city', 'region', 'country', 'org']:
                        data.append({"label": k.title(), "val": str(v), "color": "white"})
            else:
                data.append({"label": "IP Info", "val": f"HTTP {r.status_code}", "color": "red"})
        except requests.Timeout:
            data.append({"label": "IP Info", "val": "Request timed out", "color": "red"})
        except requests.ConnectionError:
            data.append({"label": "IP Info", "val": "Connection failed", "color": "red"})
        except requests.RequestException as e:
            data.append({"label": "IP Info", "val": f"Lookup Failed: {e}", "color": "red"})

        progress_cb(0.6)
        try:
            hr_data = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip={ip}", timeout=5).json()
            status = "Compromised" if "stealers" in str(hr_data) else "Clean"
            color = "red" if status == "Compromised" else "green"
            data.append({"label": "Infostealers", "val": status, "color": color})
        except requests.Timeout:
            logger.debug("Hudson Rock request timed out")
        except requests.ConnectionError:
            logger.debug("Failed to connect to Hudson Rock")
        except requests.RequestException as e:
            logger.debug(f"Hudson Rock request failed: {e}")

        progress_cb(1.0)
        self._render_table("IP INTELLIGENCE", data)
        return {}

    def scan_email(self, email, progress_cb):
        data = []

        # 1. HIBP Breach
        hibp = self.scanner.check_hibp_breach(email)
        data.append({"label": hibp['service'], "val": hibp['details'], "color": hibp['color']})
        progress_cb(0.25)

        # 2. HIBP Paste
        paste = self.scanner.check_hibp_pastes(email)
        if paste:
            data.append({"label": paste['service'], "val": paste['details'], "color": paste['color']})
        progress_cb(0.5)

        # 3. Other Services (Async)
        def sub_progress(p):
            progress_cb(0.5 + (p * 0.5))

        others = self.scanner.run_all_scans(email, progress_callback=sub_progress)
        for res in others:
            data.append({"label": res['service'], "val": res['details'], "color": res.get('color', 'white')})

        self._render_table("EMAIL ANALYSIS", data)
        return {}

    def scan_phone(self, phone, progress_cb):
        data = []
        progress_cb(0.1)
        try:
            # Attempt parsing (Handle missing +)
            try:
                p = phonenumbers.parse(phone, None)
            except phonenumbers.NumberParseException:
                if not phone.startswith("+"):
                    p = phonenumbers.parse("+" + phone, None)
                else:
                    raise

            # Core Validity Checks
            valid = phonenumbers.is_valid_number(p)
            possible = phonenumbers.is_possible_number(p)

            data.append({"label": "Valid", "val": str(valid), "color": "green" if valid else "red"})
            data.append({"label": "Possible", "val": str(possible), "color": "green" if possible else "yellow"})
            progress_cb(0.3)

            # Formatting
            fmt = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            data.append({"label": "Format", "val": fmt, "color": "white"})

            # Number Type (Mobile, Fixed, etc.)
            nt = phonenumbers.number_type(p)
            type_map = {
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "UAN",
                phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
                phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
            }
            data.append({"label": "Type", "val": type_map.get(nt, "Unknown"), "color": "white"})

            # Region & Carrier
            region = geocoder.description_for_number(p, 'en')
            if region:
                data.append({"label": "Region", "val": region, "color": "white"})

            car = carrier.name_for_number(p, 'en')
            if car:
                data.append({"label": "Carrier", "val": car, "color": "white"})
            progress_cb(0.6)

            # HIBP Phone Check
            e164_phone = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
            hibp = self.scanner.check_hibp_breach(e164_phone)
            data.append({"label": "HIBP Check", "val": hibp['details'], "color": hibp['color']})

        except phonenumbers.NumberParseException as e:
            data.append({"label": "Error", "val": f"Invalid Format: {str(e)}", "color": "red"})
        except Exception as e:
            data.append({"label": "Error", "val": f"Error: {str(e)}", "color": "red"})

        progress_cb(1.0)
        self._render_table("PHONE INTELLIGENCE", data)
        return {}

    def scan_domain(self, domain, progress_cb):
        data = []
        progress_cb(0.2)
        try:
            a_recs = [str(x) for x in dns.resolver.resolve(domain, 'A')]
            data.append({"label": "A Records", "val": ', '.join(a_recs[:3]), "color": "white"})
        except dns.resolver.NXDOMAIN:
            data.append({"label": "A Records", "val": "Domain not found", "color": "yellow"})
        except dns.resolver.NoAnswer:
            data.append({"label": "A Records", "val": "No A records", "color": "yellow"})
        except dns.resolver.Timeout:
            data.append({"label": "A Records", "val": "DNS timeout", "color": "red"})
        except Exception as e:
            logger.debug(f"DNS lookup failed: {e}")

        progress_cb(0.5)
        # HIBP Domain Check
        hibp = self.scanner.check_hibp_domain(domain)
        if hibp:
            data.append({"label": "HIBP Domain", "val": hibp['details'], "color": hibp['color']})

        progress_cb(1.0)
        self._render_table("DOMAIN RECON", data)
        return {}

    def scan_username(self, username, progress_cb):
        data = []
        progress_cb(0.1)

        hibp = self.scanner.check_hibp_breach(username)
        if hibp and hibp['status'] != "Clean":
             data.append({"label": "HIBP Check", "val": hibp['details'], "color": hibp['color']})

        sites = {
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://www.instagram.com/{username}/"
        }
        total = len(sites)
        completed = 0

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(requests.get, url, timeout=5): name for name, url in sites.items()}
            for f in as_completed(futures):
                name = futures[f]
                try:
                    if f.result().status_code == 200:
                        data.append({"label": name, "val": "FOUND", "color": "green"})
                except requests.Timeout:
                    logger.debug(f"{name} request timed out")
                except requests.ConnectionError:
                    logger.debug(f"Failed to connect to {name}")
                except requests.RequestException as e:
                    logger.debug(f"{name} request failed: {e}")
                completed += 1
                progress_cb(0.2 + (completed/total * 0.8))

        self._render_table("USERNAME ENUMERATION", data)
        return {}

    def scan_address(self, address, progress_cb):
        data = []
        progress_cb(0.2)
        try:
            headers = {'User-Agent': 'XSINT-Tool/2.1'}
            params = {
                'q': address, 'format': 'json', 'addressdetails': 1,
                'limit': 1, 'accept-language': 'en-US,en;q=0.5'
            }
            r = requests.get("https://nominatim.openstreetmap.org/search", params=params, headers=headers, timeout=10)
            progress_cb(0.8)
            if r.status_code == 200 and r.json():
                res = r.json()[0]
                data.append({"label": "Formatted", "val": res.get('display_name'), "color": "white"})
                data.append({"label": "Type", "val": res.get('type', 'N/A').capitalize(), "color": "white"})
                data.append({"label": "Coordinates", "val": f"{res.get('lat')}, {res.get('lon')}", "color": "white"})
            else:
                data.append({"label": "Status", "val": "Not Found", "color": "yellow"})
        except requests.Timeout:
            data.append({"label": "Error", "val": "Request timed out", "color": "red"})
        except requests.ConnectionError:
            data.append({"label": "Error", "val": "Connection failed", "color": "red"})
        except Exception as e:
            data.append({"label": "Error", "val": str(e), "color": "red"})

        progress_cb(1.0)
        self._render_table("ADDRESS INTELLIGENCE", data)
        return {}

# --- TUI ---
class CursesTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.log_buffer = []
        self.scroll_pos = 0
        self.input_buffer = ""
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        self.scan_progress = 0.0
        self.sparkles = []

        # State
        self.minimized = False
        self.active_menu = None
        self.settings = {
            "animations": True,
            "logging": False,
            "theme": "Ocean" # Default to Ocean
        }
        self.editing_api_key = None
        self.edit_buffer = ""

        # Themes
        self.themes = {
            "Pastel": [231, 225, 219, 213, 159, 123, 117, 120, 157, 229, 223, 224, 217],
            "Matrix": [46, 47, 48, 49, 50, 51, 82, 83, 84, 85, 86, 87, 118, 119, 120, 121],
            "Ocean": [27, 33, 39, 45, 51, 81, 87, 123, 159, 195],
            "Fire": [196, 202, 208, 214, 220, 226, 227, 228, 229]
        }
        self.theme_names = list(self.themes.keys())

        # Enable Mouse
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)

        # Initialize 256 Colors
        curses.start_color()
        curses.use_default_colors()

        # Base UI Colors (Fallback)
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_YELLOW, -1)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE) # Status Bar
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLUE) # Window Bar

        self.color_map = {"white": 1, "green": 2, "red": 3, "cyan": 4, "yellow": 5}

        self.apply_theme()

        self.engine = XSINT(self.log_callback)
        self.banner_frame = 0

        self.ascii_banner = [
            "██╗  ██╗███████╗██╗███╗   ██╗████████╗",
            "╚██╗██╔╝██╔════╝██║████╗  ██║╚══██╔══╝",
            " ╚███╔╝ ███████╗██║██╔██╗ ██║   ██║   ",
            " ██╔██╗ ╚════██║██║██║╚██╗██║   ██║   ",
            "██╔╝ ██╗███████║██║██║ ╚████║   ██║   ",
            "╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   "
        ]

    def apply_theme(self):
        spectrum = self.themes[self.settings["theme"]]
        self.spectrum_len = len(spectrum)

        # 1. Gradient Pairs (20+)
        for i, color_idx in enumerate(spectrum):
            if curses.COLORS > 8:
                curses.init_pair(20 + i, color_idx, -1)
            else:
                curses.init_pair(20 + i, (i % 7) + 1, -1)

        # 2. Main UI Theme Color (Pair 1 & 8)
        if curses.COLORS > 8:
            main_color = spectrum[len(spectrum)//2]
            curses.init_pair(1, main_color, -1)
            curses.init_pair(8, main_color, -1)
        else:
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(8, curses.COLOR_CYAN, -1)

    def log_callback(self, text, color="white"):
        cp = self.color_map.get(color, 1)
        for line in text.split('\n'):
            self.scan_queue.put((line, cp))

    def update_progress(self, val):
        self.scan_progress = val

    def run_scan(self, target, t_type):
        self.is_scanning = True
        self.scan_progress = 0.0
        try:
            if t_type == "IP": self.engine.scan_ip(target, self.update_progress)
            elif t_type == "EMAIL": self.engine.scan_email(target, self.update_progress)
            elif t_type == "PHONE": self.engine.scan_phone(target, self.update_progress)
            elif t_type == "DOMAIN": self.engine.scan_domain(target, self.update_progress)
            elif t_type == "USERNAME": self.engine.scan_username(target, self.update_progress)
            elif t_type == "ADDRESS": self.engine.scan_address(target, self.update_progress)

            self.scan_progress = 1.0
        except Exception as e:
            self.log_callback(f"[!] Error: {e}", "red")
            logger.exception(f"Scan error: {e}")
        finally:
            time.sleep(0.5)
            self.is_scanning = False
            self.scan_progress = 0.0

    def draw_window_bar(self):
        h, w = self.stdscr.getmaxyx()
        title = " XSINT TERMINAL "
        controls = "[X]  [-]  [SETTINGS] "

        theme_color = curses.color_pair(8) | curses.A_REVERSE
        self.stdscr.attron(theme_color | curses.A_BOLD)
        self.stdscr.hline(0, 0, " ", w)
        self.stdscr.addstr(0, 2, title)
        self.stdscr.addstr(0, w - len(controls) - 1, controls)
        self.stdscr.attroff(theme_color | curses.A_BOLD)

    def draw_box(self, y, x, h, w):
        theme_color = curses.color_pair(8)
        self.stdscr.attron(theme_color)
        self.stdscr.hline(y, x, curses.ACS_HLINE, w)
        self.stdscr.hline(y + h - 1, x, curses.ACS_HLINE, w)
        self.stdscr.vline(y, x, curses.ACS_VLINE, h)
        self.stdscr.vline(y, x + w - 1, curses.ACS_VLINE, h)
        self.stdscr.addch(y, x, curses.ACS_ULCORNER)
        self.stdscr.addch(y, x + w - 1, curses.ACS_URCORNER)
        self.stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER)
        self.stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
        self.stdscr.attroff(theme_color)

    def draw_settings(self):
        h, w = self.stdscr.getmaxyx()
        box_w, box_h = 50, 16
        start_y, start_x = (h - box_h)//2, (w - box_w)//2

        self.stdscr.attron(curses.color_pair(6) | curses.A_DIM)
        for y in range(box_h):
            try:
                self.stdscr.addstr(start_y + y + 1, start_x + 2, " " * box_w)
            except curses.error:
                pass
        self.stdscr.attroff(curses.color_pair(6) | curses.A_DIM)

        self.stdscr.attron(curses.color_pair(6))
        for y in range(box_h):
            try:
                self.stdscr.addstr(start_y + y, start_x, " " * box_w)
            except curses.error:
                pass
        self.stdscr.attroff(curses.color_pair(6))

        self.draw_box(start_y, start_x, box_h, box_w)

        theme_attr = curses.color_pair(8) | curses.A_BOLD
        try:
            self.stdscr.addstr(start_y + 1, start_x + (box_w - 11)//2, " PREFERENCES ", theme_attr)

            state = "[X]" if self.settings["animations"] else "[ ]"
            self.stdscr.addstr(start_y + 3, start_x + 4, f"{state} Enable Animations")

            state = "[X]" if self.settings["logging"] else "[ ]"
            self.stdscr.addstr(start_y + 5, start_x + 4, f"{state} Enable File Logging")

            self.stdscr.addstr(start_y + 7, start_x + 4, f"[ Theme: {self.settings['theme']} ] (Click to cycle)")

            self.stdscr.addstr(start_y + 9, start_x + 4, f"[ Configure API Keys > ]")

            btn = "[ CLOSE MENU ]"
            self.stdscr.addstr(start_y + 12, start_x + (box_w - len(btn))//2, btn, theme_attr | curses.A_REVERSE)
        except curses.error:
            pass

    def draw_api_config(self):
        h, w = self.stdscr.getmaxyx()
        box_w, box_h = 70, 18
        start_y, start_x = (h - box_h)//2, (w - box_w)//2

        self.stdscr.attron(curses.color_pair(6) | curses.A_DIM)
        for y in range(box_h):
            try:
                self.stdscr.addstr(start_y + y + 1, start_x + 2, " " * box_w)
            except curses.error:
                pass
        self.stdscr.attroff(curses.color_pair(6) | curses.A_DIM)

        self.stdscr.attron(curses.color_pair(6))
        for y in range(box_h):
            try:
                self.stdscr.addstr(start_y + y, start_x, " " * box_w)
            except curses.error:
                pass
        self.stdscr.attroff(curses.color_pair(6))

        self.draw_box(start_y, start_x, box_h, box_w)

        theme_attr = curses.color_pair(8) | curses.A_BOLD
        try:
            self.stdscr.addstr(start_y + 1, start_x + (box_w - 17)//2, " API CONFIGURATION ", theme_attr)

            keys = list(API_KEYS.keys())
            for idx, key in enumerate(keys):
                y_pos = start_y + 3 + idx
                val = API_KEYS[key]
                if len(val) > 25: val = val[:22] + "..."

                label = f"{key}: "
                display_val = f"[{val}]"

                row_attr = curses.A_NORMAL
                if self.editing_api_key == key:
                    display_val = f"[ {self.edit_buffer}_ ]"
                    row_attr = theme_attr

                self.stdscr.addstr(y_pos, start_x + 4, label, row_attr)
                self.stdscr.addstr(y_pos, start_x + 20, display_val, row_attr)

            btn = "[ BACK ]"
            self.stdscr.addstr(start_y + box_h - 2, start_x + (box_w - len(btn))//2, btn, theme_attr | curses.A_REVERSE)
        except curses.error:
            pass

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        if self.minimized:
            self.stdscr.attron(curses.color_pair(6))
            self.stdscr.hline(h-1, 0, " ", w)
            self.stdscr.addstr(h-1, 0, " [XSINT RUNNING] - Click [-] to restore ")
            self.stdscr.attroff(curses.color_pair(6))
            self.draw_window_bar()
            self.stdscr.refresh()
            return

        center_y, center_x = h / 2.0, w / 2.0

        # 1. Sparkles
        if self.settings["animations"]:
            if len(self.sparkles) < 200:
                for _ in range(5):
                    if random.random() < 0.2:
                        y = random.randint(1, h-1)
                        x = random.randint(0, w-1)
                        life = random.randint(50, 150)
                        self.sparkles.append([y, x, life, life])

        alive_sparkles = []
        for s in self.sparkles:
            y, x, life, max_life = s

            dy = (y - center_y) * 2.0
            dx = (x - center_x)
            dist = math.sqrt(dx*dx + dy*dy)
            val = dist * 0.15 - self.banner_frame * 0.1
            palette_idx = int((math.sin(val) + 1) / 2 * (self.spectrum_len - 1))
            pair_id = 20 + palette_idx

            progress = life / max_life
            if progress > 0.8:   char, attr = '.', curses.A_DIM
            elif progress > 0.6: char, attr = '+', curses.A_NORMAL
            elif progress > 0.4:
                if random.random() > 0.5: char, attr = '*', curses.A_BOLD
                else: char, attr = '+', curses.A_BOLD
            elif progress > 0.2: char, attr = '+', curses.A_NORMAL
            else:                char, attr = '.', curses.A_DIM

            try: self.stdscr.addch(y, x, char, curses.color_pair(pair_id) | attr)
            except curses.error: pass

            s[2] -= 1
            if s[2] > 0: alive_sparkles.append(s)
        self.sparkles = alive_sparkles

        # 2. Banner
        banner_h = len(self.ascii_banner)
        banner_w = len(self.ascii_banner[0])
        start_y = max(1, (h // 2) - 10)
        start_x = max(0, (w - banner_w) // 2)
        banner_center_y, banner_center_x = banner_h / 2.0, banner_w / 2.0

        for idx, line in enumerate(self.ascii_banner):
            for char_idx, char in enumerate(line):
                color_pair = curses.color_pair(4)
                if self.settings["animations"]:
                    dy = (idx - banner_center_y) * 2.0
                    dx = (char_idx - banner_center_x)
                    dist = math.sqrt(dx*dx + dy*dy)
                    val = dist * 0.15 - self.banner_frame * 0.1
                    palette_idx = int((math.sin(val) + 1) / 2 * (self.spectrum_len - 1))
                    color_pair = curses.color_pair(20 + palette_idx)
                try: self.stdscr.addch(start_y + idx, start_x + char_idx, char, color_pair | curses.A_BOLD)
                except curses.error: pass

        # 3. Search Box & Results
        box_w = min(80, w - 4)
        box_x = max(0, (w - box_w) // 2)
        box_y = start_y + banner_h + 2

        try:
            self.draw_box(box_y - 1, box_x, 3, box_w)
            theme_color = curses.color_pair(8)
            self.stdscr.attron(theme_color)
            self.stdscr.addstr(box_y - 1, box_x + 2, " TARGET SEARCH ", curses.A_BOLD)
            self.stdscr.attroff(theme_color)

            display = self.input_buffer
            if len(display) > box_w - 2: display = display[-(box_w-2):]
            self.stdscr.addstr(box_y, box_x + 1, display, curses.color_pair(1) | curses.A_BOLD)
        except curses.error: pass

        # 4. Progress (Live Bar)
        if self.is_scanning:
            prog_y = box_y + 2
            fill_len = int(self.scan_progress * (box_w - 2))
            bar = "[" + "=" * fill_len + ">" + " " * (box_w - fill_len - 2) + "]"
            try: self.stdscr.addstr(prog_y, box_x, bar, curses.color_pair(2))
            except curses.error: pass

        # 5. Results Box & Logs
        results_y = box_y + 4
        results_h = h - results_y - 1

        if results_h > 2:
            self.draw_box(results_y, box_x, results_h, box_w)

            if self.log_buffer:
                log_y = results_y + 1
                log_h = results_h - 2

                visible = self.log_buffer[self.scroll_pos : self.scroll_pos + log_h]
                for idx, (line, color_pair) in enumerate(visible):
                    draw_color = color_pair
                    if draw_color == 1:
                        draw_color = 8

                    safe_line = line[:box_w-4]
                    text_x = box_x + 2

                    try: self.stdscr.addstr(log_y + idx, text_x, safe_line, curses.color_pair(draw_color))
                    except curses.error: pass

        self.draw_window_bar()
        if self.active_menu == 'settings': self.draw_settings()
        elif self.active_menu == 'api_config': self.draw_api_config()

        if not self.active_menu:
            try:
                display_len = len(self.input_buffer)
                if display_len > box_w - 2: display_len = box_w - 2
                self.stdscr.move(box_y, box_x + 1 + display_len)
            except curses.error: pass

        self.stdscr.refresh()

    def handle_mouse(self, x, y):
        h, w = self.stdscr.getmaxyx()

        if self.active_menu == 'settings':
            box_w, box_h = 50, 16
            start_y, start_x = (h - box_h)//2, (w - box_w)//2

            if start_x <= x <= start_x + box_w:
                ry = y - start_y
                if ry == 3: self.settings["animations"] = not self.settings["animations"]
                elif ry == 5: self.settings["logging"] = not self.settings["logging"]
                elif ry == 7:
                    current_idx = self.theme_names.index(self.settings["theme"])
                    self.settings["theme"] = self.theme_names[(current_idx + 1) % len(self.theme_names)]
                    self.apply_theme()
                elif ry == 9: self.active_menu = 'api_config'
                elif ry == 12: self.active_menu = None
            elif not (start_x <= x <= start_x + box_w and start_y <= y <= start_y + box_h):
                self.active_menu = None
            return

        if self.active_menu == 'api_config':
            box_w, box_h = 70, 18
            start_y, start_x = (h - box_h)//2, (w - box_w)//2
            keys = list(API_KEYS.keys())

            if start_x <= x <= start_x + box_w:
                ry = y - start_y
                if 3 <= ry < 3 + len(keys):
                    key_name = keys[ry - 3]
                    self.editing_api_key = key_name
                    self.edit_buffer = ""
                elif ry == box_h - 2:
                    self.active_menu = 'settings'
                    self.editing_api_key = None
            return

        if y == 0:
            start_buttons_x = w - 22
            if start_buttons_x <= x < start_buttons_x + 3: sys.exit(0)
            elif start_buttons_x + 5 <= x < start_buttons_x + 8: self.minimized = not self.minimized
            elif start_buttons_x + 10 <= x < start_buttons_x + 20: self.active_menu = 'settings'
            return

        banner_h = len(self.ascii_banner)
        start_y = max(1, (h // 2) - 10)
        box_y = start_y + banner_h + 2
        box_w = min(80, w - 4)
        box_x = max(0, (w - box_w) // 2)
        if (box_y - 1 <= y <= box_y + 1) and (box_x <= x <= box_x + box_w):
            self.active_menu = None

    def loop(self):
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)
        curses.curs_set(1)
        while True:
            while not self.scan_queue.empty():
                self.log_buffer.append(self.scan_queue.get())
                self.scroll_pos = max(0, len(self.log_buffer) - 10)

            self.draw()

            try: key = self.stdscr.getch()
            except curses.error: key = -1

            if key == curses.KEY_MOUSE:
                try:
                    _, x, y, _, _ = curses.getmouse()
                    self.handle_mouse(x, y)
                except curses.error: pass

            if key != -1 and not self.minimized:
                if self.editing_api_key:
                    if key == 10:
                        if self.edit_buffer: API_KEYS[self.editing_api_key] = self.edit_buffer
                        self.editing_api_key = None
                    elif key == 27:
                        self.editing_api_key = None
                    elif key in (curses.KEY_BACKSPACE, 127, 8):
                        self.edit_buffer = self.edit_buffer[:-1]
                    elif 32 <= key <= 126:
                        self.edit_buffer += chr(key)

                elif not self.active_menu:
                    if key == 10:
                        t = self.input_buffer.strip()
                        self.input_buffer = ""
                        if t:
                            if t.lower() in ['exit','quit']: sys.exit(0)
                            t_type = self.engine.detect_input_type(t)
                            if t_type:
                                threading.Thread(target=self.run_scan, args=(t, t_type)).start()
                            else:
                                self.log_callback("[!] Unknown format", "red")
                    elif key in (curses.KEY_BACKSPACE, 127, 8):
                        self.input_buffer = self.input_buffer[:-1]
                    elif key == curses.KEY_PPAGE:
                        self.scroll_pos = max(0, self.scroll_pos - 10)
                    elif key == curses.KEY_NPAGE:
                        self.scroll_pos = min(len(self.log_buffer) - 10, self.scroll_pos + 10)
                    elif 32 <= key <= 126:
                        self.input_buffer += chr(key)

            self.banner_frame += 1
            time.sleep(0.03)

def main():
    try:
        sys.stdout.write("\x1b]2;XSINT INTELLIGENCE\x07")
        sys.stdout.write("\x1b[8;35;100t")
        curses.wrapper(lambda stdscr: CursesTUI(stdscr).loop())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        from pathlib import Path
        error_log = Path.home() / ".xsint" / "error.log"
        error_log.parent.mkdir(parents=True, exist_ok=True)
        with open(error_log, "w") as f: f.write(str(e))

if __name__ == "__main__":
    main()
