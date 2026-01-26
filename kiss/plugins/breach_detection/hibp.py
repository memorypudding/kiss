"""Have I Been Pwned Plugin.

Checks for data breaches and pastes via the HIBP API v3.
Fully async implementation for high-performance scanning.
"""

from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata, APIKeyRequirement


class HIBPPlugin(AsyncBasePlugin):
    """Have I Been Pwned breach detection plugin (async)."""

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="hibp",
            display_name="Have I Been Pwned",
            description="Check for data breaches and pastes via HIBP API",
            version="2.0.0",
            category="Breach Detection",
            supported_scan_types=["EMAIL", "DOMAIN"],
            api_key_requirements=[
                APIKeyRequirement(
                    key_name="hibp",
                    env_var="KISS_HIBP_API_KEY",
                    display_name="HIBP API Key",
                    description="Required for breach checking via HIBP API v3",
                    signup_url="https://haveibeenpwned.com/API/Key",
                    is_required=True,
                )
            ],
            rate_limit=120,
            timeout=30,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute HIBP breach check asynchronously."""
        results: List[Dict[str, Any]] = []

        if not self.is_configured():
            results.append(
                self._create_result(
                    "HIBP Breaches",
                    "API key required - set KISS_HIBP_API_KEY",
                    threat_level="LOW",
                )
            )
            progress_callback(1.0)
            return results

        api_key = self.get_api_key("hibp")
        progress_callback(0.2)

        # Check breaches
        breach_results = await self._check_breaches_async(target, api_key)
        results.extend(breach_results)
        progress_callback(0.6)

        # Check pastes (email only)
        if scan_type.upper() == "EMAIL":
            paste_results = await self._check_pastes_async(target, api_key)
            results.extend(paste_results)

        progress_callback(1.0)
        return results

    async def _check_breaches_async(
        self, target: str, api_key: str
    ) -> List[Dict[str, Any]]:
        """Check for data breaches asynchronously."""
        results: List[Dict[str, Any]] = []

        url = f"{self.BASE_URL}/breachedaccount/{target}"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "KISS/2.0 (OSINT Tool)",
        }

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                if response.status == 200:
                    breaches = await response.json()
                    breach_names = [b.get("Name", "Unknown") for b in breaches[:5]]
                    total = len(breaches)

                    results.append(
                        self._create_result(
                            "Data Breaches",
                            f"FOUND IN {total} BREACHES: {', '.join(breach_names)}"
                            + ("..." if total > 5 else ""),
                            threat_level="HIGH" if total > 0 else None,
                        )
                    )

                    # Add breach details
                    for breach in breaches[:3]:
                        name = breach.get("Name", "Unknown")
                        date = breach.get("BreachDate", "Unknown")
                        data_classes = breach.get("DataClasses", [])
                        exposed = ", ".join(data_classes[:3])
                        if len(data_classes) > 3:
                            exposed += f" (+{len(data_classes) - 3} more)"

                        results.append(
                            self._create_result(
                                f"Breach: {name}",
                                f"Date: {date} | Exposed: {exposed}",
                                threat_level="MEDIUM",
                                metadata={
                                    "breach_name": name,
                                    "breach_date": date,
                                    "data_classes": data_classes,
                                },
                            )
                        )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "Data Breaches",
                            "No breaches found",
                        )
                    )

                elif response.status == 401:
                    results.append(
                        self._create_result(
                            "HIBP",
                            "Invalid API key",
                            threat_level="HIGH",
                        )
                    )

                elif response.status == 429:
                    results.append(
                        self._create_result(
                            "HIBP",
                            "Rate limited - try again later",
                            threat_level="LOW",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "HIBP Error",
                    f"Request failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        return results

    async def _check_pastes_async(
        self, email: str, api_key: str
    ) -> List[Dict[str, Any]]:
        """Check for pastes containing the email asynchronously."""
        results: List[Dict[str, Any]] = []

        url = f"{self.BASE_URL}/pasteaccount/{email}"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "KISS/2.0 (OSINT Tool)",
        }

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                if response.status == 200:
                    pastes = await response.json()
                    if pastes:
                        # Get paste sources
                        sources = set()
                        for paste in pastes:
                            source = paste.get("Source", "Unknown")
                            sources.add(source)

                        results.append(
                            self._create_result(
                                "Pastes",
                                f"Found in {len(pastes)} paste(s) on: {', '.join(sources)}",
                                threat_level="MEDIUM",
                                metadata={"paste_count": len(pastes), "sources": list(sources)},
                            )
                        )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "Pastes",
                            "No pastes found",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Paste Check Error",
                    f"Request failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        return results
