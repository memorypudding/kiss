import httpx
import asyncio
from xsint.config import get_config

INFO = {
    "free": [],
    "paid": ["email", "username", "phone"],
    "api_key": "intelx",
    "returns": ["breaches", "leaks", "pastes", "documents"],
    "themes": {"IntelX": {"color": "blue", "icon": "🔍"}},
}


def is_ready():
    """IntelX is key-gated: do not run before key is configured."""
    config = get_config()
    if config.get_api_key("intelx"):
        return True, ""
    return False, "set intelx API key"

async def run(session, target):
    results = []
    PARENT = "IntelX"

    config = get_config()
    api_key = config.get_api_key("intelx")

    if not api_key:
        return 0, []

    # Endpoints to try in order of privilege
    endpoints = [
        "https://2.intelx.io",      # Pro/Enterprise
        "https://free.intelx.io",   # Free Tier
        "https://public.intelx.io", # Public/Anonymous
    ]

    # Setup Proxy
    proxy = config.get("proxy")
    proxies_dict = {"http://": proxy, "https://": proxy} if proxy else None

    # Common Headers
    headers = {
        "x-key": api_key,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

    # Search Payload (Intelligent Search)
    payload = {
        "term": target,
        "maxresults": 10,
        "media": 0, # 0 = All Media Types
        "sort": 2,  # 2 = Sort by Date
        "terminate": []
    }

    async with httpx.AsyncClient(proxies=proxies_dict, verify=False, timeout=30) as client:
        search_id = None
        working_endpoint = None

        # 1. Initiate Search (Find working endpoint)
        for endpoint in endpoints:
            try:
                resp = await client.post(f"{endpoint}/intelligent/search", json=payload, headers=headers)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("id"):
                        search_id = data["id"]
                        working_endpoint = endpoint
                        break # Success
                elif resp.status_code == 401:
                    continue # Try next endpoint if unauthorized
                    
            except Exception:
                continue

        if not search_id:
            # If search fails to start (Auth error), we still report the error
            return 1, [{"label": "IntelX", "value": "Authentication failed (Check API Key)", "source": PARENT, "risk": "low"}]

        # 2. Retrieve Results
        try:
            # We explicitly ask for 10 results
            url = f"{working_endpoint}/intelligent/search/result?id={search_id}&limit=10&statistics=1&previewlines=8"
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json()
                records = data.get("records", [])
                
                if records:
                    count = len(records)
                    results.append({
                        "label": "Records Found", 
                        "value": str(count), 
                        "source": PARENT, 
                        "risk": "high"
                    })

                    for i, record in enumerate(records[:5]):
                        name = record.get("name") or record.get("key", "Untitled")
                        date = record.get("date", "Unknown Date")[:10] # Clean timestamp
                        bucket = record.get("bucket", "Unknown Source")
                        
                        # Clean up the name if it's too long
                        if len(name) > 50:
                            name = name[:47] + "..."

                        results.append({
                            "label": f"Result {i + 1}",
                            "value": f"{name} ({bucket}, {date})",
                            "source": PARENT,
                            "risk": "medium"
                        })

                    if count > 5:
                        results.append({
                            "label": "More",
                            "value": f"+{count - 5} more records",
                            "source": PARENT,
                            "risk": "medium"
                        })
                # If no records, we do NOTHING (results remains empty)
                
            else:
                return 1, [{"label": "Error", "value": f"API Error: {resp.status_code}", "source": PARENT, "risk": "low"}]

        except Exception as e:
            return 1, [{"label": "Error", "value": str(e), "source": PARENT, "risk": "high"}]

    return 0, results
