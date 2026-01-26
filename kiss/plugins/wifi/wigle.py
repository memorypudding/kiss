"""WiGLE WiFi Network Lookup Plugin.

Uses WiGLE.net API to lookup WiFi network information based on BSSID or SSID.
WiGLE is a community-driven WiFi network database with global coverage.
"""

import base64
import re
from typing import Any, Callable, Dict, List, Optional

from ..async_base import AsyncBasePlugin, PluginMetadata, APIKeyRequirement


class WiGLEPlugin(AsyncBasePlugin):
    """WiGLE WiFi network lookup plugin.

    WiGLE (Wireless Geographic Logging Engine) maintains a database of
    WiFi networks collected by volunteers worldwide. This plugin queries
    that database for network information and location data.
    """

    BASE_URL = "https://api.wigle.net/api/v2"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="wigle",
            display_name="WiGLE",
            description="Lookup WiFi networks via WiGLE.net database",
            version="1.0.0",
            category="WiFi Intelligence",
            supported_scan_types=["WIFI"],
            api_key_requirements=[
                APIKeyRequirement(
                    key_name="wigle_name",
                    env_var="KISS_WIGLE_API_NAME",
                    display_name="WiGLE API Name",
                    description="WiGLE API name (username)",
                    signup_url="https://wigle.net/account",
                    is_required=True,
                ),
                APIKeyRequirement(
                    key_name="wigle_token",
                    env_var="KISS_WIGLE_API_TOKEN",
                    display_name="WiGLE API Token",
                    description="WiGLE API token (password)",
                    signup_url="https://wigle.net/account",
                    is_required=True,
                ),
            ],
            rate_limit=10,  # WiGLE has strict rate limits
            timeout=30,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute WiGLE network lookup.

        Args:
            target: BSSID, SSID, or combined format
            scan_type: Should be "WIFI"
            progress_callback: Progress callback function

        Returns:
            List of result dicts with network information
        """
        results: List[Dict[str, Any]] = []
        progress_callback(0.1)

        # Check API credentials
        api_name = self.get_api_key("wigle_name")
        api_token = self.get_api_key("wigle_token")

        if not api_name or not api_token:
            results.append(
                self._create_result(
                    "Configuration Error",
                    "WiGLE API credentials not configured",
                    threat_level="HIGH",
                )
            )
            progress_callback(1.0)
            return results

        progress_callback(0.2)

        # Parse target
        bssid, ssid = self._parse_wifi_target(target)

        # Determine search type
        if bssid and self._validate_bssid(bssid):
            results.extend(
                await self._search_by_bssid(bssid, ssid, api_name, api_token, progress_callback)
            )
        elif ssid:
            results.extend(
                await self._search_by_ssid(ssid, api_name, api_token, progress_callback)
            )
        else:
            results.append(
                self._create_result(
                    "Validation Error",
                    "Please provide a valid BSSID or SSID",
                    threat_level="HIGH",
                )
            )

        progress_callback(1.0)
        return results

    async def _search_by_bssid(
        self,
        bssid: str,
        ssid: Optional[str],
        api_name: str,
        api_token: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Search WiGLE by BSSID.

        Args:
            bssid: MAC address to search
            ssid: Optional SSID for filtering
            api_name: WiGLE API name
            api_token: WiGLE API token
            progress_callback: Progress callback

        Returns:
            List of results
        """
        results = []

        # Add BSSID info
        results.append(
            self._create_result(
                "BSSID",
                bssid.upper(),
            )
        )

        if ssid:
            results.append(
                self._create_result(
                    "SSID",
                    ssid,
                )
            )

        progress_callback(0.4)

        # Prepare auth header (Basic auth with API name:token)
        auth_string = f"{api_name}:{api_token}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_bytes}",
            "Accept": "application/json",
        }

        # Build query params
        # WiGLE wants BSSID without colons for netid search
        netid = bssid.replace(":", "").upper()

        url = f"{self.BASE_URL}/network/detail"
        params = {"netid": netid}

        if ssid:
            params["ssid"] = ssid

        progress_callback(0.5)

        try:
            async with self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.7)

                if response.status == 200:
                    data = await response.json()

                    if data.get("success"):
                        results.extend(self._process_network_detail(data))
                    else:
                        message = data.get("message", "Unknown error")
                        results.append(
                            self._create_result(
                                "WiGLE Response",
                                message,
                                threat_level="LOW",
                            )
                        )

                elif response.status == 401:
                    results.append(
                        self._create_result(
                            "Authentication Error",
                            "Invalid WiGLE credentials",
                            threat_level="HIGH",
                        )
                    )

                elif response.status == 429:
                    results.append(
                        self._create_result(
                            "Rate Limit",
                            "WiGLE rate limit exceeded. Try again later.",
                            threat_level="MEDIUM",
                        )
                    )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "Not Found",
                            "Network not found in WiGLE database",
                            threat_level="LOW",
                        )
                    )

                else:
                    results.append(
                        self._create_result(
                            "API Error",
                            f"Unexpected response: HTTP {response.status}",
                            threat_level="MEDIUM",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Network Error",
                    f"Request failed: {str(e)}",
                    threat_level="MEDIUM",
                )
            )

        return results

    async def _search_by_ssid(
        self,
        ssid: str,
        api_name: str,
        api_token: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Search WiGLE by SSID.

        Args:
            ssid: Network name to search
            api_name: WiGLE API name
            api_token: WiGLE API token
            progress_callback: Progress callback

        Returns:
            List of results
        """
        results = []

        results.append(
            self._create_result(
                "SSID Search",
                ssid,
            )
        )

        progress_callback(0.4)

        # Prepare auth header
        auth_string = f"{api_name}:{api_token}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_bytes}",
            "Accept": "application/json",
        }

        url = f"{self.BASE_URL}/network/search"
        params = {
            "ssid": ssid,
            "resultsPerPage": 10,
        }

        progress_callback(0.5)

        try:
            async with self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.7)

                if response.status == 200:
                    data = await response.json()

                    if data.get("success"):
                        networks = data.get("results", [])
                        total = data.get("totalResults", 0)

                        results.append(
                            self._create_result(
                                "Networks Found",
                                f"{total} network(s) with this SSID",
                            )
                        )

                        # Process first few results
                        for i, network in enumerate(networks[:5]):
                            results.extend(
                                self._process_network_result(network, i + 1)
                            )

                    else:
                        message = data.get("message", "Unknown error")
                        results.append(
                            self._create_result(
                                "WiGLE Response",
                                message,
                                threat_level="LOW",
                            )
                        )

                elif response.status == 401:
                    results.append(
                        self._create_result(
                            "Authentication Error",
                            "Invalid WiGLE credentials",
                            threat_level="HIGH",
                        )
                    )

                elif response.status == 429:
                    results.append(
                        self._create_result(
                            "Rate Limit",
                            "WiGLE rate limit exceeded",
                            threat_level="MEDIUM",
                        )
                    )

                else:
                    results.append(
                        self._create_result(
                            "API Error",
                            f"HTTP {response.status}",
                            threat_level="MEDIUM",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Network Error",
                    f"Request failed: {str(e)}",
                    threat_level="MEDIUM",
                )
            )

        return results

    def _process_network_detail(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process WiGLE network detail response.

        Args:
            data: API response data

        Returns:
            List of results
        """
        results = []

        results_data = data.get("results", [])
        if not results_data:
            results.append(
                self._create_result(
                    "Status",
                    "Network not found in WiGLE database",
                )
            )
            return results

        network = results_data[0] if isinstance(results_data, list) else results_data

        # SSID
        ssid = network.get("ssid")
        if ssid:
            results.append(
                self._create_result(
                    "Network Name",
                    ssid,
                )
            )

        # Location
        lat = network.get("trilat")
        lng = network.get("trilong")
        if lat and lng:
            results.append(
                self._create_result(
                    "Coordinates",
                    f"{lat}, {lng}",
                    metadata={"lat": lat, "lng": lng},
                )
            )

            maps_url = f"https://www.google.com/maps?q={lat},{lng}"
            results.append(
                self._create_result(
                    "Google Maps",
                    maps_url,
                )
            )

        # Address info
        road = network.get("road")
        city = network.get("city")
        region = network.get("region")
        country = network.get("country")

        address_parts = [p for p in [road, city, region, country] if p]
        if address_parts:
            results.append(
                self._create_result(
                    "Address",
                    ", ".join(address_parts),
                )
            )

        # Encryption
        encryption = network.get("encryption")
        if encryption:
            # Assess security
            threat_level = None
            if encryption.lower() in ["open", "none", "wep"]:
                threat_level = "HIGH"
            elif "wpa" in encryption.lower() and "wpa2" not in encryption.lower():
                threat_level = "MEDIUM"

            results.append(
                self._create_result(
                    "Encryption",
                    encryption,
                    threat_level=threat_level,
                )
            )

        # Channel
        channel = network.get("channel")
        if channel:
            results.append(
                self._create_result(
                    "Channel",
                    str(channel),
                )
            )

        # Frequency
        frequency = network.get("frequency")
        if frequency:
            band = "2.4 GHz" if frequency < 3000 else "5 GHz"
            results.append(
                self._create_result(
                    "Frequency",
                    f"{frequency} MHz ({band})",
                )
            )

        # First/Last seen
        first_seen = network.get("firsttime")
        last_seen = network.get("lasttime")

        if first_seen:
            results.append(
                self._create_result(
                    "First Seen",
                    first_seen,
                )
            )

        if last_seen:
            results.append(
                self._create_result(
                    "Last Seen",
                    last_seen,
                )
            )

        # Network type
        net_type = network.get("type")
        if net_type:
            results.append(
                self._create_result(
                    "Network Type",
                    net_type,
                )
            )

        return results

    def _process_network_result(
        self, network: Dict[str, Any], index: int
    ) -> List[Dict[str, Any]]:
        """Process a single network from search results.

        Args:
            network: Network data
            index: Result index

        Returns:
            List of results
        """
        results = []

        netid = network.get("netid", "")
        ssid = network.get("ssid", "")
        lat = network.get("trilat")
        lng = network.get("trilong")
        city = network.get("city")
        country = network.get("country")

        # Format location
        location_parts = []
        if city:
            location_parts.append(city)
        if country:
            location_parts.append(country)

        location_str = ", ".join(location_parts) if location_parts else "Unknown"

        # Format BSSID
        if netid:
            bssid = ":".join(
                [netid[i : i + 2] for i in range(0, len(netid), 2)]
            ).upper()
        else:
            bssid = "Unknown"

        results.append(
            self._create_result(
                f"Result #{index}",
                f"BSSID: {bssid} | Location: {location_str}",
                metadata={
                    "bssid": bssid,
                    "ssid": ssid,
                    "lat": lat,
                    "lng": lng,
                },
            )
        )

        return results

    def _parse_wifi_target(self, target: str) -> tuple:
        """Parse WiFi target string.

        Args:
            target: Input string

        Returns:
            Tuple of (bssid, ssid)
        """
        target = target.strip()
        bssid = None
        ssid = None

        # Check for query format
        if "bssid:" in target.lower() or "ssid:" in target.lower():
            bssid_match = re.search(
                r'bssid:\s*"?([0-9A-Fa-f:.-]+)"?', target, re.IGNORECASE
            )
            if bssid_match:
                bssid = bssid_match.group(1)

            ssid_match = re.search(r'ssid:\s*"([^"]+)"', target, re.IGNORECASE)
            if not ssid_match:
                ssid_match = re.search(r"ssid:\s*(\S+)", target, re.IGNORECASE)
            if ssid_match:
                ssid = ssid_match.group(1)

        elif "|" in target:
            parts = target.split("|", 1)
            bssid = parts[0].strip()
            if len(parts) > 1:
                ssid = parts[1].strip()

        else:
            # Check if it looks like a BSSID
            if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", target):
                bssid = target
            else:
                # Assume it's an SSID
                ssid = target

        if bssid:
            bssid = bssid.replace("-", ":").upper()

        return bssid, ssid

    def _validate_bssid(self, bssid: str) -> bool:
        """Validate BSSID format."""
        pattern = r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(pattern, bssid))
