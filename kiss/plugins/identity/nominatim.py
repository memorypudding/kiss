"""Nominatim Plugin.

Geocodes physical addresses using OpenStreetMap's Nominatim service.
Fully async implementation for high-performance scanning.
"""

from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata


class NominatimPlugin(AsyncBasePlugin):
    """Nominatim geocoding plugin (async)."""

    BASE_URL = "https://nominatim.openstreetmap.org"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="nominatim",
            display_name="Nominatim (OSM)",
            description="Geocode addresses via OpenStreetMap",
            version="2.0.0",
            category="Identity Lookup",
            supported_scan_types=["ADDRESS"],
            api_key_requirements=[],  # No API key required
            rate_limit=60,  # Nominatim asks for max 1 req/sec
            timeout=30,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute address geocoding asynchronously."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.2)

        url = f"{self.BASE_URL}/search"
        params = {
            "q": target,
            "format": "json",
            "limit": 1,
            "addressdetails": 1,
            "extratags": 1,
        }

        # Nominatim requires a valid User-Agent
        headers = {
            "User-Agent": "KISS/2.0 (OSINT Tool)",
        }

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.6)

                if response.status == 200:
                    data = await response.json()

                    if data:
                        location = data[0]

                        # Formatted address
                        display_name = location.get("display_name", "")
                        if display_name:
                            results.append(
                                self._create_result(
                                    "Formatted Address",
                                    display_name,
                                )
                            )

                        # Coordinates
                        lat = location.get("lat", "")
                        lon = location.get("lon", "")
                        if lat and lon:
                            results.append(
                                self._create_result(
                                    "Coordinates",
                                    f"{lat}, {lon}",
                                    metadata={"lat": float(lat), "lng": float(lon)},
                                )
                            )

                            # Add Google Maps link
                            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                            results.append(
                                self._create_result(
                                    "Google Maps",
                                    maps_url,
                                )
                            )

                        # Address components
                        addr = location.get("address", {})

                        # Country
                        country = addr.get("country", "")
                        country_code = addr.get("country_code", "").upper()
                        if country:
                            value = country
                            if country_code:
                                value += f" ({country_code})"
                            results.append(
                                self._create_result(
                                    "Country",
                                    value,
                                    metadata={"country_code": country_code},
                                )
                            )

                        # State/Province
                        state = addr.get("state", addr.get("province", ""))
                        if state:
                            results.append(
                                self._create_result(
                                    "State/Province",
                                    state,
                                )
                            )

                        # City
                        city = addr.get("city", addr.get("town", addr.get("village", "")))
                        if city:
                            results.append(
                                self._create_result(
                                    "City",
                                    city,
                                )
                            )

                        # Postcode
                        postcode = addr.get("postcode", "")
                        if postcode:
                            results.append(
                                self._create_result(
                                    "Postal Code",
                                    postcode,
                                )
                            )

                        # Place type
                        place_type = location.get("type", "")
                        place_class = location.get("class", "")
                        if place_type or place_class:
                            results.append(
                                self._create_result(
                                    "Place Type",
                                    f"{place_class}/{place_type}".strip("/"),
                                )
                            )

                        # Bounding box
                        bbox = location.get("boundingbox", [])
                        if len(bbox) == 4:
                            results.append(
                                self._create_result(
                                    "Bounding Box",
                                    f"[{bbox[0]}, {bbox[2]}] to [{bbox[1]}, {bbox[3]}]",
                                )
                            )

                        # OSM info
                        osm_type = location.get("osm_type", "")
                        osm_id = location.get("osm_id", "")
                        if osm_type and osm_id:
                            results.append(
                                self._create_result(
                                    "OSM Reference",
                                    f"{osm_type}/{osm_id}",
                                )
                            )

                    else:
                        results.append(
                            self._create_result(
                                "Geocoding",
                                "Address not found",
                            )
                        )

        except Exception as e:
            results.append(
                self._create_result(
                    "Geocoding Error",
                    f"Failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        progress_callback(1.0)
        return results
