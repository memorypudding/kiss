"""Google Geolocation API Plugin.

Uses Google's Geolocation API to lookup WiFi access point locations
based on BSSID (MAC address) and optional SSID.
"""

import re
from typing import Any, Callable, Dict, List, Optional

from ..async_base import AsyncBasePlugin, PluginMetadata, APIKeyRequirement


class GoogleGeolocationPlugin(AsyncBasePlugin):
    """Google Geolocation API plugin for WiFi AP location lookup.

    Google's Geolocation API can determine location based on:
    - WiFi access points (BSSID/MAC address)
    - Cell towers
    - IP address

    This plugin focuses on WiFi AP lookup using BSSID.
    """

    BASE_URL = "https://www.googleapis.com/geolocation/v1/geolocate"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="google_geolocation",
            display_name="Google Geolocation",
            description="Lookup WiFi access point locations via Google Geolocation API",
            version="1.0.0",
            category="WiFi Intelligence",
            supported_scan_types=["WIFI"],
            api_key_requirements=[
                APIKeyRequirement(
                    key_name="google_geolocation",
                    env_var="KISS_GOOGLE_GEOLOCATION_API_KEY",
                    display_name="Google Geolocation API Key",
                    description="Required for WiFi AP geolocation lookups",
                    signup_url="https://console.cloud.google.com/apis/credentials",
                    is_required=True,
                ),
            ],
            rate_limit=100,  # Google allows high rate limits with valid API key
            timeout=15,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute WiFi geolocation lookup.

        Args:
            target: BSSID (MAC address) or "BSSID|SSID" format
            scan_type: Should be "WIFI"
            progress_callback: Progress callback function

        Returns:
            List of result dicts with location information
        """
        results: List[Dict[str, Any]] = []
        progress_callback(0.1)

        # Check API key
        api_key = self.get_api_key("google_geolocation")
        if not api_key:
            results.append(
                self._create_result(
                    "Configuration Error",
                    "Google Geolocation API key not configured",
                    threat_level="HIGH",
                )
            )
            progress_callback(1.0)
            return results

        progress_callback(0.2)

        # Parse target - can be "BSSID" or "BSSID|SSID" or "ssid:NAME bssid:MAC"
        bssid, ssid = self._parse_wifi_target(target)

        if not bssid:
            results.append(
                self._create_result(
                    "Validation Error",
                    "Invalid BSSID format. Expected: AA:BB:CC:DD:EE:FF",
                    threat_level="HIGH",
                )
            )
            progress_callback(1.0)
            return results

        # Validate BSSID format
        if not self._validate_bssid(bssid):
            results.append(
                self._create_result(
                    "Validation Error",
                    f"Invalid BSSID format: {bssid}",
                    threat_level="HIGH",
                )
            )
            progress_callback(1.0)
            return results

        progress_callback(0.3)

        # Add parsed info
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

        # Identify vendor from MAC OUI
        vendor = self._lookup_oui(bssid)
        if vendor:
            results.append(
                self._create_result(
                    "Vendor (OUI)",
                    vendor,
                )
            )

        progress_callback(0.4)

        # Build request payload
        wifi_access_point = {"macAddress": bssid.upper()}
        if ssid:
            # Note: Google API doesn't use SSID for lookup, but we include it for reference
            pass

        payload = {
            "wifiAccessPoints": [wifi_access_point],
            "considerIp": False,  # Don't fall back to IP geolocation
        }

        progress_callback(0.5)

        # Make API request
        url = f"{self.BASE_URL}?key={api_key}"

        try:
            async with self.session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.7)

                if response.status == 200:
                    data = await response.json()
                    results.extend(self._process_response(data))

                elif response.status == 400:
                    error_data = await response.json()
                    error_msg = error_data.get("error", {}).get(
                        "message", "Bad request"
                    )
                    results.append(
                        self._create_result(
                            "API Error",
                            f"Bad request: {error_msg}",
                            threat_level="MEDIUM",
                        )
                    )

                elif response.status == 403:
                    results.append(
                        self._create_result(
                            "API Error",
                            "API key invalid or quota exceeded",
                            threat_level="HIGH",
                        )
                    )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "Location",
                            "No location data found for this BSSID",
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

        progress_callback(1.0)
        return results

    def _parse_wifi_target(self, target: str) -> tuple:
        """Parse WiFi target string into BSSID and SSID.

        Supports formats:
        - "AA:BB:CC:DD:EE:FF" (BSSID only)
        - "AA:BB:CC:DD:EE:FF|MyNetwork" (BSSID|SSID)
        - "bssid:AA:BB:CC:DD:EE:FF" (query format)
        - "bssid:AA:BB:CC:DD:EE:FF ssid:MyNetwork" (query format)

        Args:
            target: Input string

        Returns:
            Tuple of (bssid, ssid) where ssid may be None
        """
        target = target.strip()
        bssid = None
        ssid = None

        # Check for query format
        if "bssid:" in target.lower():
            # Extract BSSID
            bssid_match = re.search(
                r'bssid:\s*"?([0-9A-Fa-f:.-]+)"?', target, re.IGNORECASE
            )
            if bssid_match:
                bssid = bssid_match.group(1)

            # Extract SSID if present
            ssid_match = re.search(r'ssid:\s*"([^"]+)"', target, re.IGNORECASE)
            if not ssid_match:
                ssid_match = re.search(
                    r"ssid:\s*(\S+)", target, re.IGNORECASE
                )
            if ssid_match:
                ssid = ssid_match.group(1)

        # Check for pipe separator format
        elif "|" in target:
            parts = target.split("|", 1)
            bssid = parts[0].strip()
            if len(parts) > 1:
                ssid = parts[1].strip()

        # Plain BSSID
        else:
            bssid = target

        # Normalize BSSID format (convert dashes to colons)
        if bssid:
            bssid = bssid.replace("-", ":").upper()

        return bssid, ssid

    def _validate_bssid(self, bssid: str) -> bool:
        """Validate BSSID/MAC address format.

        Args:
            bssid: MAC address string

        Returns:
            True if valid format
        """
        pattern = r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(pattern, bssid))

    def _lookup_oui(self, bssid: str) -> Optional[str]:
        """Lookup vendor from MAC OUI (first 3 octets).

        Args:
            bssid: MAC address

        Returns:
            Vendor name or None
        """
        # Common OUI database (subset)
        # In production, this should use a full OUI database
        oui_database = {
            "00:00:0C": "Cisco Systems",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0A:95": "Apple",
            "00:0D:93": "Apple",
            "00:11:24": "Apple",
            "00:14:51": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1B:63": "Apple",
            "00:1C:B3": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1E:C2": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:25:00": "Apple",
            "00:25:4B": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:4A": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "00:30:65": "Apple",
            "00:50:E4": "Apple",
            "00:1A:2B": "Ayecom Technology",
            "00:1E:58": "D-Link",
            "00:1F:33": "Netgear",
            "00:22:6B": "Cisco-Linksys",
            "00:24:01": "D-Link",
            "00:26:5A": "D-Link",
            "00:26:F2": "Netgear",
            "00:1D:7E": "Cisco-Linksys",
            "00:18:39": "Cisco-Linksys",
            "00:1A:70": "Cisco-Linksys",
            "00:21:29": "Cisco-Linksys",
            "00:22:75": "Belkin",
            "00:1C:DF": "Belkin",
            "00:17:3F": "Belkin",
            "00:30:BD": "Belkin",
            "94:10:3E": "Belkin",
            "C0:56:27": "Belkin",
            "08:86:3B": "Belkin",
            "B4:75:0E": "Belkin",
            "00:14:BF": "Linksys",
            "00:16:B6": "Cisco-Linksys",
            "00:18:F8": "Cisco-Linksys",
            "00:1A:A2": "Cisco-Linksys",
            "00:1C:10": "Cisco-Linksys",
            "00:1D:7E": "Cisco-Linksys",
            "00:21:29": "Cisco-Linksys",
            "00:22:6B": "Cisco-Linksys",
            "00:23:69": "Cisco-Linksys",
            "00:25:9C": "Cisco-Linksys",
            "20:AA:4B": "Cisco-Linksys",
            "58:6D:8F": "Cisco-Linksys",
            "68:7F:74": "Cisco-Linksys",
            "C0:C1:C0": "Cisco-Linksys",
            "E8:04:62": "Cisco-Linksys",
            "00:09:5B": "Netgear",
            "00:0F:B5": "Netgear",
            "00:14:6C": "Netgear",
            "00:18:4D": "Netgear",
            "00:1B:2F": "Netgear",
            "00:1E:2A": "Netgear",
            "00:1F:33": "Netgear",
            "00:22:3F": "Netgear",
            "00:24:B2": "Netgear",
            "00:26:F2": "Netgear",
            "20:4E:7F": "Netgear",
            "2C:B0:5D": "Netgear",
            "30:46:9A": "Netgear",
            "44:94:FC": "Netgear",
            "6C:B0:CE": "Netgear",
            "84:1B:5E": "Netgear",
            "9C:D3:6D": "Netgear",
            "A0:21:B7": "Netgear",
            "A4:2B:8C": "Netgear",
            "C0:3F:0E": "Netgear",
            "C4:3D:C7": "Netgear",
            "E0:46:9A": "Netgear",
            "E0:91:F5": "Netgear",
            "E4:F4:C6": "Netgear",
            "00:0B:86": "Aruba Networks",
            "00:1A:1E": "Aruba Networks",
            "00:24:6C": "Aruba Networks",
            "04:BD:88": "Aruba Networks",
            "18:64:72": "Aruba Networks",
            "24:DE:C6": "Aruba Networks",
            "40:E3:D6": "Aruba Networks",
            "6C:F3:7F": "Aruba Networks",
            "84:D4:7E": "Aruba Networks",
            "94:B4:0F": "Aruba Networks",
            "9C:1C:12": "Aruba Networks",
            "A8:BD:27": "Aruba Networks",
            "AC:A3:1E": "Aruba Networks",
            "B4:5D:50": "Aruba Networks",
            "D8:C7:C8": "Aruba Networks",
            "00:09:0F": "Fortinet",
            "00:1B:21": "Intel",
            "00:1C:C0": "Intel",
            "00:1D:E0": "Intel",
            "00:1E:64": "Intel",
            "00:1E:65": "Intel",
            "00:1F:3B": "Intel",
            "00:1F:3C": "Intel",
            "00:20:A6": "Intel",
            "00:21:5C": "Intel",
            "00:21:5D": "Intel",
            "00:21:6A": "Intel",
            "00:21:6B": "Intel",
            "00:22:FA": "Intel",
            "00:22:FB": "Intel",
            "00:23:14": "Intel",
            "00:23:15": "Intel",
            "00:24:D6": "Intel",
            "00:24:D7": "Intel",
            "00:26:C6": "Intel",
            "00:26:C7": "Intel",
            "00:27:10": "Intel",
            "24:77:03": "Intel",
            "34:02:86": "Intel",
            "3C:97:0E": "Intel",
            "4C:34:88": "Intel",
            "58:91:CF": "Intel",
            "5C:51:4F": "Intel",
            "60:6C:66": "Intel",
            "68:05:CA": "Intel",
            "6C:88:14": "Intel",
            "78:92:9C": "Intel",
            "7C:5C:F8": "Intel",
            "80:86:F2": "Intel",
            "84:3A:4B": "Intel",
            "8C:70:5A": "Intel",
            "A0:A8:CD": "Intel",
            "A4:34:D9": "Intel",
            "AC:7B:A1": "Intel",
            "B4:B5:2F": "Intel",
            "BC:77:37": "Intel",
            "C8:0A:A9": "Intel",
            "CC:3D:82": "Intel",
            "D0:7E:35": "Intel",
            "DC:53:60": "Intel",
            "E8:2A:EA": "Intel",
            "F4:06:69": "Intel",
            "F8:16:54": "Intel",
        }

        # Extract OUI (first 3 octets)
        oui = bssid[:8].upper()
        return oui_database.get(oui)

    def _process_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process Google Geolocation API response.

        Args:
            data: API response JSON

        Returns:
            List of result dicts
        """
        results = []

        location = data.get("location", {})
        accuracy = data.get("accuracy")

        lat = location.get("lat")
        lng = location.get("lng")

        if lat is not None and lng is not None:
            results.append(
                self._create_result(
                    "Coordinates",
                    f"{lat}, {lng}",
                    metadata={"lat": lat, "lng": lng},
                )
            )

            # Add Google Maps link
            maps_url = f"https://www.google.com/maps?q={lat},{lng}"
            results.append(
                self._create_result(
                    "Google Maps",
                    maps_url,
                )
            )

        if accuracy:
            # Interpret accuracy
            if accuracy < 50:
                accuracy_desc = "High (within 50m)"
            elif accuracy < 200:
                accuracy_desc = "Medium (within 200m)"
            elif accuracy < 1000:
                accuracy_desc = "Low (within 1km)"
            else:
                accuracy_desc = f"Very Low ({accuracy}m radius)"

            results.append(
                self._create_result(
                    "Accuracy",
                    f"{accuracy}m - {accuracy_desc}",
                    metadata={"accuracy_meters": accuracy},
                )
            )

        if not results:
            results.append(
                self._create_result(
                    "Location",
                    "No location data returned",
                    threat_level="LOW",
                )
            )

        return results
