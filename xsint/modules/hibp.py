import httpx
import asyncio
from xsint.config import get_config

INFO = {
    "free": ["hash"],
    "paid": ["email", "username", "phone"],
    "api_key": "hibp",
    "returns": ["breaches", "breach names", "breach dates"],
    "themes": {"HIBP": {"color": "yellow", "icon": "⚠ "}},
}

MAX_RETRIES = 3


async def run(session, target):
    """
    HIBP Module
    Migrated to HTTPX for better proxy support and connection stability.
    """
    config = get_config()
    key = config.get_api_key("hibp")

    if not key:
        return 1, []

    # 1. Setup Proxy
    proxy = config.get("proxy")
    proxies_dict = {"http://": proxy, "https://": proxy} if proxy else None

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
    headers = {
        "hibp-api-key": key,
        "user-agent": "XSINT",
    }

    async with httpx.AsyncClient(proxies=proxies_dict, verify=False, timeout=30.0) as client:
        try:
            for attempt in range(MAX_RETRIES):
                resp = await client.get(url, headers=headers)

                if resp.status_code == 429:
                    wait = int(resp.headers.get("retry-after", 2))
                    await asyncio.sleep(wait)
                    continue

                if resp.status_code == 404:
                    return 0, [
                        {
                            "label": "Breaches",
                            "value": "None found",
                            "source": "HIBP",
                            "risk": "low",
                        }
                    ]

                if resp.status_code == 401:
                    return 1, []

                if resp.status_code == 200:
                    breaches = resp.json()
                    results = [
                        {
                            "label": "Breaches",
                            "value": str(len(breaches)),
                            "source": "HIBP",
                            "risk": "high" if breaches else "low",
                        }
                    ]
                    for b in breaches[:10]:
                        results.append(
                            {
                                "label": "Breach",
                                "value": f"{b.get('Name', 'Unknown')} ({b.get('BreachDate', 'N/A')})",
                                "source": "HIBP",
                                "risk": "high",
                            }
                        )
                    if len(breaches) > 10:
                        results.append(
                            {
                                "label": "Note",
                                "value": f"+{len(breaches) - 10} more breaches",
                                "source": "HIBP",
                                "risk": "high",
                            }
                        )
                    return 0, results

            return 1, [
                {
                    "label": "HIBP",
                    "value": "Rate limited after retries",
                    "source": "HIBP",
                    "risk": "low",
                }
            ]
        except Exception as e:
            return 1, [
                {"label": "HIBP Error", "value": str(e), "source": "HIBP", "risk": "low"}
            ]
