import phonenumbers
from phonenumbers import geocoder, carrier, timezone

INFO = {
    "free": ["phone"],
    "returns": ["location", "carrier", "line type", "timezone"],
}

async def run(session, target):
    try:
        if not target.startswith("+"):
            target = f"+{target}"

        try:
            number = phonenumbers.parse(target, None)
        except phonenumbers.NumberParseException:
            return 1, ["Could not parse number. Ensure it includes country code (e.g., +1)"]

        if not phonenumbers.is_valid_number(number):
            return 1, ["Invalid Phone Number (Check country code or length)"]

        results = []

        results.append({
            "label": "International",
            "value": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "source": "libphonenumbers",
            "risk": "low"
        })

        region_name = geocoder.description_for_number(number, "en")
        if region_name:
            results.append({"label": "Location", "value": region_name, "source": "libphonenumbers", "risk": "low"})

        carrier_name = carrier.name_for_number(number, "en")
        if carrier_name:
            results.append({"label": "Carrier", "value": carrier_name, "source": "libphonenumbers", "risk": "low"})

        num_type_code = phonenumbers.number_type(number)
        type_map = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
            phonenumbers.PhoneNumberType.VOIP: "VoIP (Internet)",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        }
        type_str = type_map.get(num_type_code, "Unknown/Other")
        risk_level = "medium" if "VoIP" in type_str else "low"
        results.append({"label": "Line Type", "value": type_str, "source": "libphonenumbers", "risk": risk_level})

        timezones = timezone.time_zones_for_number(number)
        if timezones:
            results.append({"label": "Timezone", "value": ", ".join(timezones), "source": "libphonenumbers", "risk": "low"})

        return 0, results

    except Exception as e:
        return 1, [str(e)]
