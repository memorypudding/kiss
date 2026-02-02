from kiss.config import get_config

INFO = {
    "free": ["email", "username", "phone", "ip", "hash", "name", "id", "ssn", "passport"],
    "api_key": "9ghz",
    "returns": ["breaches"],
}

async def run(session, target):
    config = get_config()
    key = config.get_api_key("9ghz")

    if key:
        url = "https://9ghz.com/api/v1/query_detail"
        headers = {"X-Auth-Key": key}
    else:
        url = "https://9ghz.com/api/v1/query"
        headers = {}

    try:
        async with session.post(url, json={"keyword": target}, headers=headers) as resp:
            if resp.status != 200:
                return 1, [{"label": "9Ghz", "value": f"HTTP {resp.status}", "source": "9Ghz", "risk": "low"}]

            data = await resp.json()
            # Response: {"code":0,"data":{"data":[...]}} or {"data":[...]} or [...]
            breaches = data
            if isinstance(breaches, dict):
                breaches = breaches.get("data", breaches)
            if isinstance(breaches, dict):
                breaches = breaches.get("data", [])
            if not isinstance(breaches, list):
                breaches = []

            if not breaches:
                return 0, [{"label": "Breaches", "value": "None found", "source": "9Ghz", "risk": "low"}]

            results = [
                {"label": "Breaches", "value": str(len(breaches)), "source": "9Ghz", "risk": "high"}
            ]
            for b in breaches[:10]:
                title = b.get("title") or b.get("domain") or "Unknown"
                date = b.get("breach_date", "N/A")
                results.append({"label": "Breach", "value": f"{title} ({date})", "source": "9Ghz", "risk": "high"})
            if len(breaches) > 10:
                results.append({"label": "Note", "value": f"+{len(breaches) - 10} more breaches", "source": "9Ghz", "risk": "high"})
            return 0, results
    except Exception as e:
        return 1, [{"label": "9Ghz Error", "value": str(e), "source": "9Ghz", "risk": "low"}]
