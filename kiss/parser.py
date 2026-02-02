import re
import ipaddress
import phonenumbers

def detect_target_type(target):
    target = target.strip()
    
    # --- 1. EXPLICIT PREFIX CHECK ---
    # format: "type:value"
    if ":" in target:
        prefix, value = target.split(":", 1)
        prefix = prefix.lower()
        
        # Map short prefixes to folder names
        if prefix in ["addr", "address", "loc"]:
            return "address", value.strip()
        if prefix in ["user", "username", "u"]:
            return "username", value.strip()
        if prefix in ["phone", "tel"]:
            return "phone", value.strip()
        if prefix in ["ip", "host"]:
            return "ip", value.strip()
        if prefix in ["email", "mail"]:
            return "email", value.strip()
        if prefix in ["name", "n"]:
            return "name", value.strip()
        if prefix in ["id", "ic"]:
            return "id", value.strip()
        if prefix in ["ssn"]:
            return "ssn", value.strip()
        if prefix in ["passport", "pp"]:
            return "passport", value.strip()
        if prefix in ["hash", "h"]:
            return "hash", value.strip()

    # --- 2. STRICT AUTO-DETECTION ---
    
    # IP Address (Cannot be confused with anything else)
    try:
        ipaddress.ip_address(target)
        return "ip", target
    except ValueError:
        pass

    # Email (Strict Regex)
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", target):
        return "email", target

    # Phone (Must be valid E.164 to be auto-detected)
    try:
        pn = phonenumbers.parse(target, None)
        if phonenumbers.is_valid_number(pn):
            return "phone", target
    except:
        pass

    # --- 3. REJECTION ---
    # If we are here, the input is ambiguous (e.g., "Tokyo", "admin", "12345").
    # We do NOT guess. We return None so the engine can fail gracefully.
    return None, None