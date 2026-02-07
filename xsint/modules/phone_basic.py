import phonenumbers
from phonenumbers import geocoder, carrier, timezone

INFO = {
    "free": ["phone"],
    "returns": ["formats", "country", "carrier", "line type", "timezone"],
    "themes": {
        "libphonenumbers": {"color": "cyan", "icon": "📞"}
    }
}

async def run(session, target):
    try:
        # Ensure prefix (default to + if missing, though parser usually handles this)
        if not target.startswith("+"):
            target = f"+{target}"

        try:
            number = phonenumbers.parse(target, None)
        except phonenumbers.NumberParseException:
            return 1, ["Could not parse number. Ensure it includes country code (e.g., +1)"]

        # Validity Check
        if not phonenumbers.is_valid_number(number):
            # refined error for "possible but invalid" (e.g. unassigned area code)
            if phonenumbers.is_possible_number(number):
                 return 1, ["Number structure is valid, but the number is not assigned (Invalid)."]
            return 1, ["Invalid Phone Number (Check country code or length)"]

        results = []

        # 1. Standard Formats
        e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
        national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
        
        results.append({"label": "E.164", "value": e164, "source": "libphonenumbers", "risk": "low"})
        results.append({"label": "National", "value": national, "source": "libphonenumbers", "risk": "low"})

        # 2. Region / Country
        region_code = phonenumbers.region_code_for_number(number)
        results.append({"label": "Region Code", "value": region_code, "source": "libphonenumbers", "risk": "low"})

        # 3. Geo Location
        region_name = geocoder.description_for_number(number, "en")
        if region_name:
            results.append({"label": "Location", "value": region_name, "source": "libphonenumbers", "risk": "low"})

        # 4. Carrier (Mobile/VOIP only usually)
        carrier_name = carrier.name_for_number(number, "en")
        if carrier_name:
            results.append({"label": "Carrier", "value": carrier_name, "source": "libphonenumbers", "risk": "low"})

        # 5. Line Type & Risk
        num_type_code = phonenumbers.number_type(number)
        type_map = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
            phonenumbers.PhoneNumberType.VOIP: "VoIP (Non-fixed)",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.UAN: "Universal Access Number",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        }
        type_str = type_map.get(num_type_code, "Unknown/Other")
        
        # Mark VOIP as medium risk (commonly used for burners/scams)
        risk = "medium" if num_type_code == phonenumbers.PhoneNumberType.VOIP else "low"
        results.append({"label": "Line Type", "value": type_str, "source": "libphonenumbers", "risk": risk})

        # 6. Timezones
        timezones = timezone.time_zones_for_number(number)
        if timezones:
            results.append({"label": "Timezone", "value": ", ".join(timezones), "source": "libphonenumbers", "risk": "low"})

        return 0, results

    except Exception as e:
        return 1, [str(e)]