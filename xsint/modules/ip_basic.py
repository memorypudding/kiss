import ipaddress

INFO = {
    "free": ["ip"],
    "returns": ["version", "private/public"],
    "themes": {
        "StdLib": {"color": "green", "icon": "🔌"}
    }
}

async def run(session, target):
    try:
        obj = ipaddress.ip_address(target)
        return 0, [
            {"label": "Version", "value": f"IPv{obj.version}", "source": "StdLib", "risk": "low"},
            {"label": "Private", "value": str(obj.is_private), "source": "StdLib", "risk": "medium" if not obj.is_private else "low"}
        ]
    except:
        return 1, []
