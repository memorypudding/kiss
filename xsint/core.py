import ast
import asyncio
import aiohttp
import importlib
import os
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Callable, Optional

from .parser import detect_target_type
from .config import get_config

VALID_TYPES = {
    "email",
    "username",
    "phone",
    "ip",
    "address",
    "hash",
    "name",
    "id",
    "ssn",
    "passport",
}


ProgressCallback = Callable[[Dict[str, Any]], None]


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


class XsintEngine:
    def __init__(self, proxy=None):
        self.session = None
        self.proxy = proxy or get_config().get("proxy")
        self._modules_path = os.path.join(os.path.dirname(__file__), "modules")
        env_timeout = os.getenv("XSINT_MODULE_TIMEOUT", "25").strip()
        try:
            self.module_timeout = max(5, int(env_timeout))
        except ValueError:
            self.module_timeout = 25

    async def get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            if self.proxy:
                try:
                    # Validate and parse proxy URL
                    from urllib.parse import urlparse

                    parsed = urlparse(self.proxy)

                    # Basic validation
                    if not parsed.scheme or not parsed.netloc:
                        raise ValueError(f"Invalid proxy URL format: {self.proxy}")

                    # Extract port and validate it's numeric
                    if ":" in parsed.netloc:
                        host_port = parsed.netloc.rsplit(":", 1)
                        if len(host_port) == 2:
                            try:
                                port = int(host_port[1])
                                if not (1 <= port <= 65535):
                                    raise ValueError(f"Proxy port out of range: {port}")
                            except ValueError:
                                raise ValueError(f"Invalid proxy port: {host_port[1]}")

                    # ProxyConnector handles both HTTP and SOCKS proxies
                    from aiohttp_socks import ProxyConnector

                    connector = ProxyConnector.from_url(
                        self.proxy, ssl=False, rdns=True
                    )
                    self.session = aiohttp.ClientSession(connector=connector)
                except Exception as e:
                    print(f"[!] Proxy configuration error: {e}")
                    print(f"[!] Falling back to direct connection")
                    self.session = aiohttp.ClientSession()
            else:
                self.session = aiohttp.ClientSession()
        return self.session

    async def close(self):
        if self.session:
            await self.session.close()

    @staticmethod
    def _emit_progress(
        progress_cb: Optional[ProgressCallback], event: str, **payload: Any
    ) -> None:
        if not progress_cb:
            return
        try:
            progress_cb({"event": event, **payload})
        except Exception:
            # Progress UI must never break the scan pipeline.
            pass

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
            modules.append(
                {
                    "name": filename[:-3],
                    "info": info,
                }
            )
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
            runtime_ready = True
            runtime_reason = ""

            try:
                imported = importlib.import_module(f"xsint.modules.{mod['name']}")
                runtime_ready, runtime_reason = self._module_ready(imported)
            except Exception:
                runtime_ready = False
                runtime_reason = "not installed"

            for t in free_types | paid_types:
                if t not in VALID_TYPES:
                    continue
                if t in free_types:
                    status = "active"
                elif has_key:
                    status = "active"
                else:
                    status = "locked"

                if status == "active" and not runtime_ready:
                    status = "locked"

                caps[t].append(
                    {
                        "name": mod["name"],
                        "status": status,
                        "api_key": api_key,
                        "returns": info.get("returns", []),
                        "reason": runtime_reason,
                    }
                )

        return dict(caps)

    def _module_ready(self, imported: Any) -> Tuple[bool, str]:
        checker = getattr(imported, "is_ready", None)
        if not checker or not callable(checker):
            return True, ""
        result = checker()
        if isinstance(result, tuple):
            ready = bool(result[0]) if len(result) > 0 else False
            reason = str(result[1]) if len(result) > 1 and result[1] else ""
            return ready, reason
        return bool(result), ""

    def _load_modules_for_type(
        self, target_type: str
    ) -> Tuple[List[Tuple[str, Any, Dict]], List[Dict[str, str]]]:
        """
        Import modules that are active for the given type.
        Returns a list of tuples: (module_name, run_function, info_dict)
        """
        config = get_config()
        runners = []
        skipped = []

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
                imported = importlib.import_module(f"xsint.modules.{mod['name']}")
                ready, reason = self._module_ready(imported)
                if not ready:
                    skipped.append(
                        {
                            "name": mod["name"],
                            "reason": reason or "not configured",
                        }
                    )
                    continue
                if hasattr(imported, "run") and callable(imported.run):
                    runners.append((mod["name"], imported.run, info))
            except Exception:
                pass

        return runners, skipped

    async def scan(
        self, target: str, progress_cb: Optional[ProgressCallback] = None
    ) -> Dict[str, Any]:
        target = target.strip()
        self._emit_progress(progress_cb, "detect_start", target=target)

        target_type, clean_target = detect_target_type(target)
        self._emit_progress(
            progress_cb, "detect_done", target_type=target_type, target=clean_target
        )

        if not target_type:
            self._emit_progress(progress_cb, "scan_done", status="aborted")
            return {
                "type": "AMBIGUOUS",
                "results": [],
                "themes": {},
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
                ),
            }

        runners_with_info, skipped_modules = self._load_modules_for_type(target_type)
        self._emit_progress(
            progress_cb,
            "modules_loaded",
            target_type=target_type,
            count=len(runners_with_info),
            modules=[name for name, _, _ in runners_with_info],
            skipped=skipped_modules,
        )
        if not runners_with_info:
            self._emit_progress(
                progress_cb, "scan_done", status="completed", findings=1, modules=0
            )
            return {
                "type": target_type,
                "results": [
                    {
                        "label": "Status",
                        "value": "No modules found",
                        "source": "System",
                        "risk": "low",
                    }
                ],
                "themes": {},
                "error": None,
            }

        session = await self.get_session()

        # Prepare tasks and aggregate themes from module INFO dicts
        tasks = []
        collected_themes = {}

        for module_name, func, info in runners_with_info:
            tasks.append(
                self._run_module_with_progress(
                    module_name, func, session, clean_target, progress_cb
                )
            )
            if "themes" in info:
                collected_themes.update(info["themes"])

        module_results = await asyncio.gather(*tasks, return_exceptions=False)

        final_data = []
        for module_name, res in module_results:
            if isinstance(res, Exception):
                final_data.append(
                    {
                        "label": "Error",
                        "value": str(res),
                        "source": module_name,
                        "risk": "high",
                    }
                )
                continue
            if isinstance(res, tuple) and len(res) == 2:
                status, data = res
                if isinstance(data, list):
                    final_data.extend(data)

        # Filter out empty results (e.g. "None found")
        final_data = [r for r in final_data if r.get("value") != "None found"]
        self._emit_progress(
            progress_cb,
            "scan_done",
            status="completed",
            findings=len(final_data),
            modules=len(module_results),
        )

        return {
            "type": target_type,
            "results": final_data,
            "themes": collected_themes,  # Pass collected themes to the UI
            "error": None,
        }

    async def _run_module_with_progress(
        self,
        module_name: str,
        run_func: Any,
        session: aiohttp.ClientSession,
        clean_target: str,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> Tuple[str, Any]:
        self._emit_progress(progress_cb, "module_start", module=module_name)
        try:
            result = await asyncio.wait_for(
                run_func(session, clean_target), timeout=self.module_timeout
            )
            self._emit_progress(
                progress_cb, "module_done", module=module_name, status="ok"
            )
            return module_name, result
        except asyncio.TimeoutError:
            self._emit_progress(
                progress_cb,
                "module_done",
                module=module_name,
                status="timeout",
                error=f"timeout after {self.module_timeout}s",
            )
            return module_name, (
                1,
                [
                    {
                        "label": "Timeout",
                        "value": f"Module timed out after {self.module_timeout}s",
                        "source": module_name,
                        "risk": "medium",
                    }
                ],
            )
        except Exception as e:
            self._emit_progress(
                progress_cb,
                "module_done",
                module=module_name,
                status="error",
                error=str(e),
            )
            return module_name, e
