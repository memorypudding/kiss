import httpx
import os
import json
import re
import time
import hashlib
from contextlib import redirect_stdout
from types import SimpleNamespace

# GHunt Imports
from ghunt.helpers import auth, playgames, gmaps, calendar as gcalendar
from ghunt.apis.peoplepa import PeoplePaHttp
from ghunt import config as ghunt_config
from xsint.config import get_config

INFO = {
    "free": [],
    "paid": ["email", "phone", "gaia_id"],
    "returns": ["gaia_id", "profile", "services", "maps", "calendar"],
    "themes": {
        "GHunt":     {"color": "plum2",         "icon": "👻"},
    }
}

# --- HELPER: SAPISIDHASH Generator ---
def get_sapisid_hash(sapisid_cookie, origin):
    """Generates the authorization hash signed against the specific origin."""
    timestamp = str(int(time.time()))
    payload = f"{timestamp} {sapisid_cookie} {origin}"
    sha1 = hashlib.sha1(payload.encode()).hexdigest()
    return f"SAPISIDHASH {timestamp}_{sha1}"

async def get_gmaps_profile(client, gaia_id):
    """Fetches strictly valid Profile Stats (Reviews, Photos, etc)."""
    result = {"stats": {}, "name": None}
    try:
        pb = ghunt_config.templates['gmaps_pb']['stats'].format(gaia_id)
        url = f"https://www.google.com/locationhistory/preview/mas?authuser=0&hl=en&gl=us&pb={pb}"
        req = await client.get(url)
        if req.status_code == 200:
            txt = req.text[5:] if req.text.startswith(")]}'") else req.text
            data = json.loads(txt)
            if len(data) > 16 and isinstance(data[16], list) and len(data[16]) > 0:
                if isinstance(data[16][0], str): result["name"] = data[16][0]
            
            def find_stats(obj):
                if isinstance(obj, list):
                    if len(obj) > 8 and isinstance(obj[6], str) and isinstance(obj[7], int):
                        if obj[6] in ["Reviews", "Photos", "Answers", "Ratings", "Videos", "Edits"]:
                            result["stats"][obj[6]] = obj[7]
                    for item in obj: find_stats(item)
            find_stats(data)
    except: pass
    return result

async def run(session, target):
    results = []
    PARENT = "GHunt"
    config = get_config()
    proxy = config.get("proxy")
    proxies = {"http://": proxy, "https://": proxy} if proxy else None
    
    # Base headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
        "Accept-Language": "en-US,en;q=0.5"
    }

    is_phone = False
    
    # 1. Input Detection & Cleaning
    if "@" not in target and any(char.isdigit() for char in target):
        # Heuristic: 21 digits = likely Gaia ID, otherwise Phone
        if len(re.sub(r'\D', '', target)) == 21 and target.isdigit():
             is_phone = False # Treat as Gaia ID
        else:
             is_phone = True
             # Keep only digits and the '+' sign
             target = re.sub(r'[^\d+]', '', target)

    async with httpx.AsyncClient(proxies=proxies, http2=True, headers=headers, verify=False) as client:
        try:
            with open(os.devnull, "w") as f, redirect_stdout(f):
                creds = await auth.load_and_auth(client)
        except: return 1, [{"label": "Auth", "value": "Session error", "source": PARENT, "risk": "high"}]

        found = False
        person = None

        # --- PATH A: MANUAL PHONE LOOKUP (Fixing the Origin/Auth) ---
        if is_phone:
            try:
                sapisid = creds.cookies.get("SAPISID")
                if not sapisid: raise Exception("No SAPISID")
                
                # [FIX] Use Google Contacts as the origin context
                origin = "https://contacts.google.com"
                
                ph_headers = {
                    "Authorization": get_sapisid_hash(sapisid, origin),
                    "X-Goog-Api-Key": "AIzaSyAa2odBewW-sPJu3jMORr0aNedh3YlkiQc",
                    "Origin": origin,
                    "Referer": f"{origin}/",
                    "X-Goog-AuthUser": "0"
                }
                
                params = {
                    "id": target,
                    "type": "PHONE",
                    "match_type": "EXACT", 
                    "request_mask.include_field.paths": [
                        "person.name", "person.photo", "person.email", 
                        "person.metadata", "person.in_app_reachability"
                    ],
                    "core_id_params.enable_private_names": "true"
                }

                resp = await client.get("https://people-pa.clients6.google.com/v2/people/lookup", params=params, headers=ph_headers)
                
                if resp.status_code == 200:
                    data = resp.json()
                    p_data = data.get("person", data) 
                    
                    if "personId" in p_data:
                        # Construct Dummy Person Object
                        person = SimpleNamespace()
                        person.personId = p_data.get("personId")
                        person.names = {}
                        person.profilePhotos = {}
                        person.inAppReachability = {}
                        person.sourceIds = {}

                        # Map Names
                        if "names" in p_data:
                            for n in p_data["names"]:
                                if "displayName" in n:
                                    person.names["PROFILE"] = SimpleNamespace(fullname=n["displayName"])
                                    break
                        
                        # Map Photos
                        if "photos" in p_data:
                            for p in p_data["photos"]:
                                if "url" in p:
                                    person.profilePhotos["PROFILE"] = SimpleNamespace(url=p["url"], isDefault=p.get("default", False))
                                    break
                                    
                        # Map Services
                        if "inAppReachability" in p_data:
                            apps = [app.get("appType") for app in p_data["inAppReachability"] if app.get("status") == "REACHABLE"]
                            person.inAppReachability["PROFILE"] = SimpleNamespace(apps=apps)

                        found = True
            except Exception:
                pass 

        # --- PATH B: STANDARD LOOKUP (Email / Gaia) ---
        if not found:
            try:
                people = PeoplePaHttp(creds)
                found, person = await people.people_lookup(client, target, params_template="max_details")
            except:
                pass

        if not found or not person:
            return 0, [{"label": "Status", "value": "Target not found", "source": PARENT, "risk": "low"}]

        # --- DATA OUTPUT ---
        acc = "👤 Account"
        results.append({"label": "Gaia ID", "value": person.personId, "source": PARENT, "group": acc})
        
        # --- MAPS STATS ---
        maps = await get_gmaps_profile(client, person.personId)
        
        final_name = maps.get("name")
        if not final_name and hasattr(person, "names") and "PROFILE" in person.names:
            final_name = person.names["PROFILE"].fullname
            
        if final_name:
            results.append({"label": "Name", "value": final_name, "source": PARENT, "group": acc})

        # Profile Photo
        if hasattr(person, "profilePhotos") and "PROFILE" in person.profilePhotos:
            photo = person.profilePhotos["PROFILE"]
            if not getattr(photo, "isDefault", True):
                 results.append({"label": "Profile Photo", "value": photo.url, "source": PARENT, "group": acc})

        # Services
        if hasattr(person, "inAppReachability") and "PROFILE" in person.inAppReachability:
            apps = person.inAppReachability["PROFILE"].apps
            if apps:
                results.append({"label": "Active", "value": ", ".join(apps), "source": PARENT, "group": "🛠 Services"})

        # Maps Output
        if maps["stats"]:
            grp_maps = "🗺 Maps"
            results.append({"label": "Profile", "value": f"https://www.google.com/maps/contrib/7{person.personId}", "source": PARENT, "group": grp_maps})
            
            for k, v in maps["stats"].items():
                results.append({"label": k, "value": str(v), "source": PARENT, "group": grp_maps})

    return 0, results