import httpx
import json
import asyncio
from xsint.config import get_config

INFO = {
    "free": ["email", "username", "phone", "ip", "hash", "name", "id", "ssn", "passport"],
    "api_key": "9ghz",
    "returns": ["breaches"],
    "themes": {
        "9Ghz": {"color": "red", "icon": "☢ "}
    }
}

MAX_RETRIES = 3

async def run(session, target):
    """
    9Ghz Module
    Migrated to HTTPX for better proxy support and connection stability.
    """
    config = get_config()
    key = config.get_api_key("9ghz")
    
    # 1. Setup Proxy
    proxy = config.get("proxy")
    proxies_dict = {"http://": proxy, "https://": proxy} if proxy else None

    # 2. Mimic Chrome on Windows
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://9ghz.com/"
    }

    if key:
        url = "https://9ghz.com/api/v1/query_detail"
        headers["X-Auth-Key"] = key
    else:
        url = "https://9ghz.com/api/v1/query"

    # 3. Request Loop using HTTPX
    async with httpx.AsyncClient(proxies=proxies_dict, verify=False, timeout=30.0) as client:
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.post(url, json={"keyword": target}, headers=headers)
                
                if resp.status_code == 429:
                    # Exponential backoff
                    await asyncio.sleep(2 * (attempt + 1))
                    continue

                if resp.status_code != 200:
                    if resp.status_code >= 500:
                        await asyncio.sleep(1)
                        continue
                    return 1, [{"label": "9Ghz", "value": f"HTTP {resp.status_code}", "source": "9Ghz", "risk": "low"}]

                # 4. Robust JSON Parsing
                # httpx's .json() ensures the response is fully read before parsing
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(1)
                        continue
                    return 1, [{"label": "9Ghz Error", "value": "Response truncated (Invalid JSON)", "source": "9Ghz", "risk": "low"}]

                # 5. Data Extraction
                breaches = data
                # Unwrap 'data' wrapper if present
                if isinstance(breaches, dict):
                    breaches = breaches.get("data", breaches)
                # Double check in case of nested structures
                if isinstance(breaches, dict):
                    breaches = breaches.get("data", [])
                
                if not isinstance(breaches, list):
                    breaches = []

                if not breaches:
                    return 0, [{"label": "Breaches", "value": "None found", "source": "9Ghz", "risk": "low"}]

                results = [
                    {"label": "Breaches", "value": str(len(breaches)), "source": "9Ghz", "risk": "high"}
                ]
                
                # Display Top 10
                for b in breaches[:10]:
                    title = b.get("title") or b.get("domain") or "Unknown"
                    date = b.get("breach_date", "N/A")
                    results.append({"label": "Breach", "value": f"{title} ({date})", "source": "9Ghz", "risk": "high"})
                
                if len(breaches) > 10:
                    results.append({"label": "Note", "value": f"+{len(breaches) - 10} more breaches", "source": "9Ghz", "risk": "high"})
                
                return 0, results

            except (httpx.RequestError, httpx.TimeoutException) as e:
                # Retry on connection drops
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
                return 1, [{"label": "9Ghz Error", "value": f"Connection failed: {str(e)}", "source": "9Ghz", "risk": "low"}]
            except Exception as e:
                return 1, [{"label": "9Ghz Error", "value": str(e), "source": "9Ghz", "risk": "low"}]
    
    return 1, [{"label": "9Ghz", "value": "Max retries exceeded", "source": "9Ghz", "risk": "low"}]