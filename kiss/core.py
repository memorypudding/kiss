import ast
import asyncio
import aiohttp
import importlib
import os
from collections import defaultdict
from typing import List, Dict, Any

from .parser import detect_target_type
from .config import get_config

VALID_TYPES = {"email", "username", "phone", "ip", "address", "hash", "name", "id", "ssn", "passport"}


def _parse_info(filepath):
    """Read INFO dict from a module file using ast (no import)."""
    with open(filepath, "r") as f:
        tree = ast.parse(f.read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "INFO":
                    return ast.literal_eval(node.value)
    return None


class KissEngine:
    def __init__(self, proxy=None):
        self.session = None
        self.proxy = proxy or get_config().get("proxy")
        self._modules_path = os.path.join(os.path.dirname(__file__), "modules")

    async def get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            if self.proxy:
                import ssl
                from aiohttp_socks import ProxyConnector
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                connector = ProxyConnector.from_url(self.proxy, ssl=ssl_context)
                self.session = aiohttp.ClientSession(connector=connector)
            else:
                self.session = aiohttp.ClientSession()
        return self.session

    async def close(self):
        if self.session:
            await self.session.close()

    def _scan_modules(self) -> List[Dict[str, Any]]:
        """Scan all module .py files and extract INFO dicts via ast."""
        modules = []
        if not os.path.exists(self._modules_path):
            return modules

        for filename in sorted(os.listdir(self._modules_path)):
            if not filename.endswith(".py") or filename.startswith("__"):
                continue
            filepath = os.path.join(self._modules_path, filename)
            try:
                info = _parse_info(filepath)
            except Exception:
                continue
            if not info:
                continue
            modules.append({
                "name": filename[:-3],
                "info": info,
            })
        return modules

    def get_capabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build per-type module listing from INFO dicts.
        Returns: { 'email': [{'name': ..., 'status': 'active'|'locked', 'info': ...}, ...] }
        """
        config = get_config()
        caps = defaultdict(list)

        for mod in self._scan_modules():
            info = mod["info"]
            api_key = info.get("api_key")
            has_key = config.get_api_key(api_key) is not None if api_key else True
            free_types = set(info.get("free", []))
            paid_types = set(info.get("paid", []))

            for t in free_types | paid_types:
                if t not in VALID_TYPES:
                    continue
                if t in free_types:
                    status = "active"
                elif has_key:
                    status = "active"
                else:
                    status = "locked"

                caps[t].append({
                    "name": mod["name"],
                    "status": status,
                    "api_key": api_key,
                    "returns": info.get("returns", []),
                })

        return dict(caps)

    def _load_modules_for_type(self, target_type: str) -> List[Any]:
        """Import modules that are active for the given type."""
        config = get_config()
        runners = []

        for mod in self._scan_modules():
            info = mod["info"]
            free_types = set(info.get("free", []))
            paid_types = set(info.get("paid", []))

            if target_type not in free_types | paid_types:
                continue

            # Skip locked modules (paid type without key)
            if target_type in paid_types and target_type not in free_types:
                api_key = info.get("api_key")
                if api_key and not config.get_api_key(api_key):
                    continue

            try:
                imported = importlib.import_module(f"kiss.modules.{mod['name']}")
                if hasattr(imported, "run") and callable(imported.run):
                    runners.append(imported.run)
            except Exception as e:
                print(f"[!] Error loading module {mod['name']}: {e}")

        return runners

    async def scan(self, target: str) -> Dict[str, Any]:
        target = target.strip()

        target_type, clean_target = detect_target_type(target)

        if not target_type:
            return {
                "type": "AMBIGUOUS",
                "results": [],
                "error": (
                    "Could not determine target type.\n"
                    "Please use a prefix to be specific:\n"
                    "  - email:test@test.com\n"
                    "  - user:admin\n"
                    "  - phone:+14155551234\n"
                    "  - ip:1.1.1.1\n"
                    "  - addr:Tokyo\n"
                    "  - name:John Doe\n"
                    "  - id:1234567890\n"
                    "  - ssn:123-45-6789\n"
                    "  - passport:AB1234567\n"
                    "  - hash:5f4dcc3b"
                )
            }

        runners = self._load_modules_for_type(target_type)
        if not runners:
            return {
                "type": target_type,
                "results": [{"label": "Status", "value": "No modules found", "source": "System", "risk": "low"}],
                "error": None
            }

        session = await self.get_session()
        tasks = [func(session, clean_target) for func in runners]
        module_results = await asyncio.gather(*tasks, return_exceptions=True)

        final_data = []
        for res in module_results:
            if isinstance(res, Exception):
                final_data.append({"label": "Error", "value": str(res), "source": "System", "risk": "high"})
                continue
            if isinstance(res, tuple) and len(res) == 2:
                status, data = res
                if isinstance(data, list):
                    final_data.extend(data)

        # Filter out empty results (e.g. "None found")
        final_data = [r for r in final_data if r.get("value") != "None found"]

        return {
            "type": target_type,
            "results": final_data,
            "error": None
        }
