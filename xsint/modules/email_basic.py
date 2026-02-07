import httpx
from xsint.config import get_config

INFO = {
    "free": ["email"],
    "returns": ["mx records"],
    "themes": {
        "DNS": {"color": "blue", "icon": "🌐"}
    }
}

async def run(session, target):
    """
    Email Basic Module
    Migrated to HTTPX for better proxy support and connection stability.
    """
    if "@" not in target:
        return 1, []

    domain = target.split("@")[1]
    results = []

    # Setup Proxy
    config = get_config()
    proxy = config.get("proxy")
    proxies_dict = {"http://": proxy, "https://": proxy} if proxy else None

    # Check DNS MX Records (Proof the domain actually handles email)
    url = f"https://dns.google/resolve?name={domain}&type=MX"
    try:
        async with httpx.AsyncClient(proxies=proxies_dict, verify=False, timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data:
                    # Get the top priority mail server
                    mx_records = sorted(
                        data["Answer"],
                        key=lambda x: int(x.get("data", "0").split()[0]) if "data" in x else 0
                    )
                    top_mx = mx_records[0]["data"].split()[-1].rstrip(".")

                    # Return everything under ONE source: "DNS"
                    results.append({"label": "Mail Server", "value": top_mx, "source": "DNS", "risk": "low"})

                    # Identify Provider
                    provider = "Unknown"
                    if "google" in top_mx: provider = "Google Workspace"
                    elif "outlook" in top_mx: provider = "Microsoft 365"
                    elif "proton" in top_mx: provider = "ProtonMail"

                    if provider != "Unknown":
                        results.append({"label": "Provider", "value": provider, "source": "DNS", "risk": "low"})
    except:
        pass

    if results:
        return 0, results
    return 1, []
