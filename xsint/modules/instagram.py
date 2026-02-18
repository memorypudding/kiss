import asyncio
import json
import os
import random
import re
import uuid

import aiohttp
from yarl import URL

from xsint.config import get_config

INFO = {
    "free": ["username"],
    "returns": ["recovery methods"],
    "themes": {"Instagram": {"color": "magenta", "icon": "IG"}},
}

class InstagramRecoveryWorkflow:
    USER_AGENT = "Instagram 316.0.0.38.109 Android (33/13; 420dpi; 1080x2400; Samsung; SM-G991B; o1s; exynos2100; en_US; 564219463)"
    START_APPID, UHL_APPID, UHL_REQ_APPID = "com.bloks.www.caa.ar.search.async", "com.bloks.www.caa.ar.uhl.nav.async", "com.bloks.www.caa.ar.uhl.nav"
    UHL_API_ID, UHL_BLOKS_VER = "1217981644879628", "89260ab7c284bc53283ddb1870bf272c0c189a1a497762c002b28865952b5415"
    MAX_STEPS, TOKEN_MIN_LEN = 10, 1000

    APPID_REWRITE = {
        "com.bloks.www.caa.ar.search": "com.bloks.www.caa.ar.search.async",
        "com.bloks.www.caa.ar.authentication_confirmation": "com.bloks.www.caa.ar.authentication_confirmation.async",
        "com.bloks.www.caa.ar.uhl.nav": "com.bloks.www.caa.ar.uhl.nav.async",
    }
    BLOCKED = {"com.bloks.www.caa.ar.submit_code.async"}
    
    APPID_RE = re.compile(r"com\.bloks\.www\.caa\.ar\.[a-zA-Z0-9_.]+")
    TOKEN_RE = re.compile(r"[A-Za-z0-9_+/=-]{20,}\|arm")
    METHOD_TEXT_RE = re.compile(r'"(?:text|title|subtitle|value|label)":"([^"]{3,220})"')
    EMAIL_RE = re.compile(r"[a-zA-Z0-9][\w.*]*\*+[\w.*]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    PHONE_RE = re.compile(r"[+]\d[\d\s./*-]*\*[\d\s./*-]*\d+")

    def __init__(self, username, proxy_url="", base_session=None):
        self.username, self.proxy_url = username, proxy_url
        self.base_session = base_session
        self.use_proxy = bool(proxy_url)
        self.using_shared_connector = False
        self.session = None
        self.device_id, self.text_input_id = str(uuid.uuid4()).upper(), f"{uuid.uuid4().hex[:6]}:98"
        self.machine_id = self.lsd = self.token = ""

        self.web_sessionid = os.getenv("IG_WEB_SESSIONID", "")
        self.web_ds_user_id = os.getenv("IG_WEB_DS_USER_ID", "")
        self.delay_min, self.delay_max = float(os.getenv("XSINT_IG_DELAY_MIN", "0.2")), float(os.getenv("XSINT_IG_DELAY_MAX", "0.7"))

    async def open(self):
        if self.session and not self.session.closed: return
        headers = {
            "Host": "www.instagram.com", "User-Agent": self.USER_AGENT, "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9", "Origin": "https://www.instagram.com",
            "Referer": "https://www.instagram.com/", "Content-Type": "application/x-www-form-urlencoded",
            "X-IG-App-ID": self.UHL_API_ID,
        }
        connector = None
        connector_owner = True
        # If an explicit proxy is configured, prefer per-request proxy mode
        # because local HTTP proxy tools (e.g. Burp) tend to work better there.
        if not self.use_proxy and self.base_session is not None:
            base_connector = getattr(self.base_session, "connector", None)
            if base_connector is not None and not base_connector.closed:
                connector = base_connector
                connector_owner = False
                self.using_shared_connector = True

        if connector is None:
            connector = aiohttp.TCPConnector(ssl=False)
            self.using_shared_connector = False

        self.session = aiohttp.ClientSession(
            connector=connector,
            connector_owner=connector_owner,
            timeout=aiohttp.ClientTimeout(total=20),
            headers=headers,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        )
        base = URL("https://www.instagram.com")
        cookies = {"ig_did": self.device_id}
        if self.web_sessionid: cookies["sessionid"] = self.web_sessionid
        if self.web_ds_user_id: cookies["ds_user_id"] = self.web_ds_user_id
        self.session.cookie_jar.update_cookies(cookies, base)

    async def close(self):
        if self.session and not self.session.closed: await self.session.close()

    def _cookie(self, name):
        c = self.session.cookie_jar.filter_cookies(URL("https://www.instagram.com/")).get(name) if self.session else None
        return c.value if c else ""

    def _set_cookie(self, name, value):
        if self.session: self.session.cookie_jar.update_cookies({name: value}, URL("https://www.instagram.com/"))

    async def _request(self, method, url, **kwargs):
        await self.open()
        request_proxy = None
        if not self.using_shared_connector and self.use_proxy:
            request_proxy = self.proxy_url
        for _ in range(2):
            try:
                async with self.session.request(method, url, proxy=request_proxy, **kwargs) as r:
                    return r.status, await r.text(errors="replace")
            except (aiohttp.ClientProxyConnectionError, aiohttp.ClientConnectorError):
                if self.using_shared_connector or not self.use_proxy:
                    return 0, ""
                self.use_proxy = False
                request_proxy = None
            except Exception:
                return 0, ""
        return 0, ""

    @classmethod
    def _parse_token(cls, text):
        m = cls.TOKEN_RE.findall(text.replace("for (;;);", ""))
        return max(m, key=len) if m else ""

    def _next_appid(self, text, current):
        seen = [self.APPID_REWRITE.get(r, r) for r in self.APPID_RE.findall(text)]
        return next((a for a in seen if a != current and a not in self.BLOCKED), "")

    @classmethod
    def _parse_methods(cls, text):
        dec = text.encode("utf-8", "replace").decode("unicode_escape", "replace")
        chunks = cls.METHOD_TEXT_RE.findall(dec)
        methods = [("EMAIL", m) for c in chunks for m in cls.EMAIL_RE.findall(c)]
        methods += [("SMS", m.strip()) for c in chunks for m in cls.PHONE_RE.findall(c)]
        return list(dict.fromkeys(methods))  # Deduplicate while preserving order

    @staticmethod
    def _unwrap_outer_parens(tok):
        tok = tok.strip()
        if not (tok.startswith("(") and tok.endswith(")")): return tok
        stack, match, in_str, esc = [], {}, False, False
        for i, ch in enumerate(tok):
            if in_str:
                esc, in_str = (False, in_str) if esc else (ch == '\\', ch != '"')
                continue
            if ch == '"': in_str = True
            elif ch == "(": stack.append(i)
            elif ch == ")":
                if not stack: return tok
                match[stack.pop()] = i
        
        if stack: return tok
        l, r = 0, len(tok) - 1
        while l < r and tok[l] == "(" and tok[r] == ")" and match.get(l) == r: l, r = l + 1, r - 1
        return tok[l:r + 1].strip()

    def _coerce(self, tok):
        tok = self._unwrap_outer_parens(tok)
        if not tok: return None
        if "bk.action.array.Make" in tok: return self._parse_array(tok, tok.find("bk.action.array.Make"))[0]
        if "bk.action.map.Make" in tok: return self._extract_map(tok)
        try: return json.loads(tok)
        except Exception: return {"lois_token": ""} if "lois_token" in tok else tok

    def _parse_array(self, text, start):
        i, n = start + 20, len(text)
        while i < n and text[i] in " ,": i += 1
        out, begin, depth, in_str, esc = [], i, 0, False, False
        while i < n:
            ch = text[i]
            if in_str: esc, in_str = (False, in_str) if esc else (ch == '\\', ch != '"')
            else:
                if ch == '"': in_str = True
                elif ch == "(": depth += 1
                elif ch == ")":
                    if depth == 0:
                        if tok := text[begin:i].strip().rstrip(","): out.append(self._coerce(tok))
                        return out, i + 1
                    depth -= 1
                elif ch == "," and depth == 0:
                    if tok := text[begin:i].strip(): out.append(self._coerce(tok))
                    begin = i + 1
            i += 1
        return out, n

    def _extract_map(self, text):
        ks = text.find("bk.action.array.Make")
        if ks < 0: return {}
        keys, end = self._parse_array(text, ks)
        vs = text.find("bk.action.array.Make", end)
        if not keys or vs < 0: return {}
        return dict(zip(keys, self._parse_array(text, vs)[0][:len(keys)]))

    def _dynamic_params(self, text, appid):
        if not text or not (m := re.search(r'AsyncActionWithDataManifestV2\s*,\s*"{}"'.format(re.escape(appid)), text.replace('\\"', '"'))): return None
        sec = text.replace('\\"', '"')[m.start(): m.start() + 120_000]
        
        server, client = [], []
        for m in re.finditer(r"bk\.action\.map\.Make\s*,", sec):
            if not (p := self._extract_map(sec[m.start() : m.start() + 30_000])): continue
            if "device_id" in p and "context_data" in p: server.append(p)
            if {"search_query", "lois_settings", "zero_balance_state", "aac"} & p.keys(): client.append(p)

        return {
            "server_params": max(server, key=lambda c: (100 if c.get("context_data") else 0) + (80 if c.get("device_id") else 0) + (40 if c.get("auth_method_async_params") else 0)) if server else {},
            "client_input_params": max(client, key=lambda c: (80 if "search_query" in c else 0) + (60 if "lois_settings" in c else 0) + (15 if "text_input_id" in c else 0) - (30 if "device_id" in c else 0)) if client else {},
        } if server or client else None

    def _payload(self, appid, app_type, parsed):
        sp = {
            "device_id": self.machine_id or self.device_id, "event_request_id": str(uuid.uuid4()),
            "waterfall_id": uuid.uuid4().hex, "access_flow_version": "pre_mt_behavior",
            "context_data": self.token, "is_platform_login": 0, "is_from_logged_out": 0, "is_from_logged_in_switcher": 0,
        }
        cp = {"search_query": self.username, "text_input_id": self.text_input_id, "lois_settings": {"lois_token": ""}, "zero_balance_state": None, "aac": ""}

        if parsed:
            sp |= parsed.get("server_params", {})
            cp |= parsed.get("client_input_params", {})

        if appid == self.START_APPID: sp["access_flow_version"], cp["search_screen_type"] = "F2_FLOW", "mobile"
        if app_type == "app":
            sp.update({"waterfall_id": "1", "back_nav_action": "BACK", "INTERNAL_INFRA_screen_id": ""})
            cp["machine_id"] = self.machine_id
        if appid == self.UHL_APPID: sp["source"], cp["is_from_logged_in_switcher"] = "confirm_your_account_dialog", True
        if appid == "com.bloks.www.caa.ar.authentication_confirmation.async":
            sp["is_auth_method_rejected"], cp = 1, {"cloud_trust_token": None, "lois_settings": {"lois_token": ""}}

        sp["device_id"] = sp.get("device_id") or self.machine_id or self.device_id
        sp["context_data"] = sp.get("context_data") or self.token
        return {"server_params": sp, "client_input_params": cp}

    async def _post(self, appid, payload, app_type):
        if self.delay_max > 0: await asyncio.sleep(random.uniform(self.delay_min, self.delay_max))

        if appid == self.UHL_APPID:
            h = {"X-CSRFToken": self._cookie("csrftoken"), "X-Ig-App-Id": self.UHL_API_ID, "X-Bloks-Version-Id": self.UHL_BLOKS_VER, "X-Ig-Device-Id": self.device_id, "X-Fb-Friendly-Name": "api", "X-Requested-With": "XMLHttpRequest"}
            signed = {"params": json.dumps(payload, separators=(",", ":")), "bloks_versioning_id": self.UHL_BLOKS_VER, "bk_client_context": '{"styles_id":"instagram","pixel_ratio":3.0}'}
            return await self._request("POST", f"https://www.instagram.com/api/v1/bloks/async_action/{appid}/", headers=h, data={"signed_body": "SIGNATURE." + json.dumps(signed, separators=(",", ":"))})

        data = {"__a": "1", "__hs": "", "__comet_req": "6", "lsd": self.lsd, "params": json.dumps({"params": json.dumps(payload, separators=(",", ":"))})}
        params = {"appid": self.UHL_REQ_APPID if "uhl.nav" in appid else appid, "type": "app" if "uhl.nav" in appid else app_type, "__bkv": "549e3ff69ef67a13c41791a62b2c14e2a0979de8af853baac859e53cd47312a8"}
        return await self._request("POST", "https://www.instagram.com/async/wbloks/fetch/", params=params, data=data, headers={"Sec-Fetch-Site": "."})

    async def run(self):
        status, text = await self._request("GET", "https://www.instagram.com/accounts/password/reset/", headers={"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
        if status != 200 or not self._cookie("datr") or not (m := re.search(r'"machine_id":"([^"]+)"', text)) or not (l := re.search(r'\["LSD",\[\],\{"token":"(.*?)"\}', text)):
            return []
        self.machine_id, self.lsd = m.group(1), l.group(1)
        self._set_cookie("mid", self.machine_id)
        if not self._cookie("csrftoken"): self._set_cookie("csrftoken", self.lsd)

        appid, prev_text, seen, methods = await self._search(), "", set(), []
        for _ in range(self.MAX_STEPS):
            if not appid or appid in seen or appid in self.BLOCKED: break
            seen.add(appid)

            is_async, app_type = appid.endswith(".async") and appid != self.UHL_APPID, "action" if (appid.endswith(".async") and appid != self.UHL_APPID) else "app"
            status, text = await self._post(appid, self._payload(appid, app_type, self._dynamic_params(prev_text, appid) if (is_async and prev_text) else None), app_type)
            if status == 0 or not text: break

            if token := self._parse_token(text): self.token = token
            methods.extend(self._parse_methods(text))
            prev_text, appid = text, self._next_appid(text, appid)

        return list(dict.fromkeys(methods))

    async def _search(self):
        status, text = await self._post(self.START_APPID, self._payload(self.START_APPID, "action", None), "action")
        if status != 200 or not (token := self._parse_token(text)) or len(token) < self.TOKEN_MIN_LEN: return ""
        self.token = token
        return self._next_appid(text, self.START_APPID)


async def _run_workflow_once(target, proxy_url, base_session, use_base_session=True):
    flow = InstagramRecoveryWorkflow(
        target,
        proxy_url=proxy_url,
        base_session=base_session if use_base_session else None,
    )
    await flow.open()
    try:
        return await flow.run()
    finally:
        await flow.close()


async def run(session, target):
    configured_proxy = get_config().get("proxy")
    methods = await _run_workflow_once(target, configured_proxy, session, use_base_session=True)

    # Proxy paths (especially local interceptors) can alter IG flow responses.
    # If proxy mode finds nothing, retry once without proxy before returning empty.
    if not methods and configured_proxy:
        methods = await _run_workflow_once(target, "", session, use_base_session=False)

    if not methods:
        return 0, []

    rows = [{"label": "Recovery options", "value": str(len(methods)), "source": "Instagram", "risk": "medium"}]
    rows.extend([{"label": k, "value": v, "source": "Instagram", "risk": "medium"} for k, v in methods[:10]])
    if len(methods) > 10:
        rows.append({"label": "More", "value": f"+{len(methods) - 10} more", "source": "Instagram", "risk": "low"})
    return 0, rows
