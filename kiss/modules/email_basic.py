import re

INFO = {
    "free": ["email"],
    "returns": ["syntax validation", "domain"],
}

async def run(session, target):
    if "@" in target:
        domain = target.split("@")[1]
        return 0, [
            {"label": "Syntax", "value": "Valid", "source": "Regex", "risk": "low"},
            {"label": "Domain", "value": domain, "source": "Parser", "risk": "low"}
        ]
    return 1, []
