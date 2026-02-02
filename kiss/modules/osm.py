from geopy.geocoders import Nominatim
from geopy.adapters import AioHTTPAdapter
import re

INFO = {
    "free": ["address"],
    "returns": ["address", "coordinates", "location type"],
}

async def run(session, target):
    async with Nominatim(
        user_agent="KISS-OSINT",
        adapter_factory=lambda proxies, ssl_context: AioHTTPAdapter(proxies=proxies, ssl_context=ssl_context)
    ) as geolocator:

        async def search(query):
            try:
                return await geolocator.geocode(query, language="en", addressdetails=True)
            except:
                return None

        location = await search(target)

        if not location and "," in target:
            parts = [p.strip() for p in target.split(",")]
            if len(parts) > 1:
                location = await search(", ".join(parts[:-1]))
            if not location and len(parts) >= 2:
                location = await search(", ".join(parts[:2]))

        if not location:
            zip_match = re.search(r'\b\d{3}[-]\d{4}\b|\b\d{5}\b', target)
            if zip_match:
                location = await search(zip_match.group(0))

        if not location:
            return 1, ["Address not found"]

        return 0, [
            {"label": "Address", "value": location.address, "source": "geopy", "risk": "low"},
            {"label": "Coordinates", "value": f"{location.latitude}, {location.longitude}", "source": "geopy", "risk": "low"},
            {"label": "Raw Type", "value": location.raw.get("type", "N/A"), "source": "geopy", "risk": "low"}
        ]
