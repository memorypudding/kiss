INFO = {
    "free": ["username"],
    "returns": ["platform", "real name", "bio"],
}

async def run(session, target):
    url = f"https://api.github.com/users/{target}"
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                return 0, [
                    {"label": "Platform", "value": "GitHub", "source": "API", "risk": "low"},
                    {"label": "Real Name", "value": data.get("name", "N/A"), "source": "GitHub", "risk": "low"},
                    {"label": "Bio", "value": data.get("bio", "N/A"), "source": "GitHub", "risk": "low"}
                ]
    except:
        pass
    return 1, []
