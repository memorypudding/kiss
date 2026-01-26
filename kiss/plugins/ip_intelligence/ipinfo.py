"""IPInfo Plugin.

Provides IP geolocation and network intelligence.
Fully async implementation for high-performance scanning.
"""

from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata, APIKeyRequirement


class IPInfoPlugin(AsyncBasePlugin):
    """IPInfo geolocation plugin (async)."""

    BASE_URL = "https://ipinfo.io"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="ipinfo",
            display_name="IPInfo",
            description="IP geolocation and network intelligence",
            version="2.0.0",
            category="IP Intelligence",
            supported_scan_types=["IP"],
            api_key_requirements=[
                APIKeyRequirement(
                    key_name="ipinfo",
                    env_var="KISS_IPINFO_API_KEY",
                    display_name="IPInfo API Key",
                    description="Optional - increases rate limits",
                    signup_url="https://ipinfo.io/signup",
                    is_required=False,  # Works without key, just rate limited
                )
            ],
            rate_limit=1000,
            timeout=30,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute IP lookup asynchronously."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.2)

        url = f"{self.BASE_URL}/{target}/json"

        # Add auth header if API key available
        headers = {}
        api_key = self.get_api_key("ipinfo")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.6)

                if response.status == 200:
                    data = await response.json()

                    # Location info
                    city = data.get("city", "")
                    region = data.get("region", "")
                    country = data.get("country", "")

                    if city or region or country:
                        location_parts = [p for p in [city, region, country] if p]
                        results.append(
                            self._create_result(
                                "Location",
                                ", ".join(location_parts),
                                metadata={
                                    "city": city,
                                    "region": region,
                                    "country": country,
                                },
                            )
                        )

                    # Organization/ISP
                    org = data.get("org", "")
                    if org:
                        # Parse ASN if present (format: "AS12345 Company Name")
                        asn = ""
                        org_name = org
                        if org.startswith("AS"):
                            parts = org.split(" ", 1)
                            asn = parts[0]
                            org_name = parts[1] if len(parts) > 1 else org

                        results.append(
                            self._create_result(
                                "Organization",
                                org_name,
                                metadata={"asn": asn, "full_org": org},
                            )
                        )

                        if asn:
                            results.append(
                                self._create_result(
                                    "ASN",
                                    asn,
                                )
                            )

                    # Hostname
                    hostname = data.get("hostname", "")
                    if hostname:
                        results.append(
                            self._create_result(
                                "Hostname",
                                hostname,
                            )
                        )

                    # Coordinates
                    loc = data.get("loc", "")
                    if loc:
                        results.append(
                            self._create_result(
                                "Coordinates",
                                loc,
                                metadata={"lat_lng": loc},
                            )
                        )

                        # Add Google Maps link
                        maps_url = f"https://www.google.com/maps?q={loc}"
                        results.append(
                            self._create_result(
                                "Google Maps",
                                maps_url,
                            )
                        )

                    # Timezone
                    timezone = data.get("timezone", "")
                    if timezone:
                        results.append(
                            self._create_result(
                                "Timezone",
                                timezone,
                            )
                        )

                    # Postal code
                    postal = data.get("postal", "")
                    if postal:
                        results.append(
                            self._create_result(
                                "Postal Code",
                                postal,
                            )
                        )

                    # Check for privacy flags (VPN, Proxy, etc.)
                    privacy = data.get("privacy", {})
                    if privacy:
                        privacy_flags = []

                        if privacy.get("vpn"):
                            privacy_flags.append("VPN")
                            results.append(
                                self._create_result(
                                    "VPN Detected",
                                    "This IP is associated with a VPN service",
                                    threat_level="MEDIUM",
                                )
                            )

                        if privacy.get("proxy"):
                            privacy_flags.append("Proxy")
                            results.append(
                                self._create_result(
                                    "Proxy Detected",
                                    "This IP is associated with a proxy service",
                                    threat_level="MEDIUM",
                                )
                            )

                        if privacy.get("tor"):
                            privacy_flags.append("Tor")
                            results.append(
                                self._create_result(
                                    "Tor Exit Node",
                                    "This IP is a Tor exit node",
                                    threat_level="HIGH",
                                )
                            )

                        if privacy.get("relay"):
                            privacy_flags.append("Relay")
                            results.append(
                                self._create_result(
                                    "Relay Service",
                                    "This IP is part of a relay service (e.g., iCloud Private Relay)",
                                    threat_level="LOW",
                                )
                            )

                        if privacy.get("hosting"):
                            privacy_flags.append("Hosting")
                            results.append(
                                self._create_result(
                                    "Hosting Provider",
                                    "This IP belongs to a hosting/cloud provider",
                                )
                            )

                    # Abuse contact info (if available with paid API)
                    abuse = data.get("abuse", {})
                    if abuse:
                        abuse_email = abuse.get("email", "")
                        if abuse_email:
                            results.append(
                                self._create_result(
                                    "Abuse Contact",
                                    abuse_email,
                                )
                            )

                    # Company info (if available with paid API)
                    company = data.get("company", {})
                    if company:
                        company_name = company.get("name", "")
                        company_type = company.get("type", "")
                        if company_name:
                            value = company_name
                            if company_type:
                                value += f" ({company_type})"
                            results.append(
                                self._create_result(
                                    "Company",
                                    value,
                                )
                            )

                elif response.status == 429:
                    results.append(
                        self._create_result(
                            "IPInfo",
                            "Rate limited - add API key for higher limits",
                            threat_level="LOW",
                        )
                    )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "IPInfo",
                            "IP address not found",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "IPInfo Error",
                    f"Lookup failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        progress_callback(1.0)
        return results
