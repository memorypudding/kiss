"""Hudson Rock Plugin.

Checks for credentials in stealer malware logs.
Fully async implementation for high-performance scanning.
"""

from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata


class HudsonRockPlugin(AsyncBasePlugin):
    """Hudson Rock stealer malware check plugin (async)."""

    BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="hudson_rock",
            display_name="Hudson Rock",
            description="Check for credentials in stealer malware logs",
            version="2.0.0",
            category="Breach Detection",
            supported_scan_types=["EMAIL", "IP", "PHONE", "DOMAIN"],
            api_key_requirements=[],  # No API key required
            rate_limit=30,
            timeout=30,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute Hudson Rock stealer check asynchronously."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.2)

        scan_type_upper = scan_type.upper()

        if scan_type_upper == "EMAIL":
            results.extend(await self._check_email_async(target))
        elif scan_type_upper == "IP":
            results.extend(await self._check_ip_async(target))
        elif scan_type_upper == "PHONE":
            results.extend(await self._check_phone_async(target))
        elif scan_type_upper == "DOMAIN":
            results.extend(await self._check_domain_async(target))

        progress_callback(1.0)
        return results

    async def _check_email_async(self, email: str) -> List[Dict[str, Any]]:
        """Check email in stealer logs asynchronously."""
        url = f"{self.BASE_URL}/search-by-email"
        params = {"email": email}
        return await self._make_check_async(url, params, "email")

    async def _check_ip_async(self, ip: str) -> List[Dict[str, Any]]:
        """Check IP in stealer logs asynchronously."""
        url = f"{self.BASE_URL}/search-by-ip"
        params = {"ip": ip}
        return await self._make_check_async(url, params, "IP")

    async def _check_phone_async(self, phone: str) -> List[Dict[str, Any]]:
        """Check phone in stealer logs asynchronously."""
        # Clean phone number
        clean_phone = "".join(c for c in phone if c.isdigit() or c == "+")
        url = f"{self.BASE_URL}/search-by-phone"
        params = {"phone": clean_phone}
        return await self._make_check_async(url, params, "phone")

    async def _check_domain_async(self, domain: str) -> List[Dict[str, Any]]:
        """Check domain in stealer logs asynchronously."""
        url = f"{self.BASE_URL}/search-by-domain"
        params = {"domain": domain}
        return await self._make_check_async(url, params, "domain")

    async def _make_check_async(
        self, url: str, params: Dict[str, str], check_type: str
    ) -> List[Dict[str, Any]]:
        """Make a stealer log check request asynchronously."""
        results: List[Dict[str, Any]] = []

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                params=params,
                timeout=self.metadata.timeout,
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    # Check if data was found
                    if data.get("stealers") or data.get("total_results", 0) > 0:
                        count = data.get("total_results", len(data.get("stealers", [])))
                        results.append(
                            self._create_result(
                                "Stealer Malware",
                                f"COMPROMISED - Found in {count} stealer log(s)",
                                threat_level="CRITICAL",
                                metadata={"total_results": count},
                            )
                        )

                        # Add stealer details if available
                        stealers = data.get("stealers", [])
                        for stealer in stealers[:3]:
                            stealer_type = stealer.get("type", "Unknown")
                            date = stealer.get("date_compromised", "Unknown")
                            computer_name = stealer.get("computer_name", "")

                            value = f"Compromised: {date}"
                            if computer_name:
                                value += f" | Machine: {computer_name}"

                            results.append(
                                self._create_result(
                                    f"Stealer: {stealer_type}",
                                    value,
                                    threat_level="HIGH",
                                    metadata={
                                        "stealer_type": stealer_type,
                                        "date_compromised": date,
                                        "computer_name": computer_name,
                                    },
                                )
                            )
                    else:
                        results.append(
                            self._create_result(
                                "Stealer Malware",
                                "Not found in stealer logs",
                            )
                        )

                else:
                    results.append(
                        self._create_result(
                            "Stealer Malware",
                            "Not found in stealer logs",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Stealer Malware",
                    f"Check failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        return results
