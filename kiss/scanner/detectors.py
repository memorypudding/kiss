"""XSINT Input Type Detectors.

Utilities for detecting the type of input (IP, email, phone, etc.).
"""

import re
import ipaddress
from typing import Optional, Tuple, Any

from kiss.constants import INPUT_PATTERNS, ScanType


def detect_input_type(input_value: str) -> Optional[str]:
    """
    Detect the type of input based on pattern matching.

    Args:
        input_value: The input string to analyze

    Returns:
        The detected scan type as a string, or None if no match
    """
    if not input_value or not isinstance(input_value, str):
        return None

    input_value = input_value.strip()

    # Check for IP address (most specific)
    if is_ip_address(input_value):
        return ScanType.IP.value

    # Check for BSSID/WiFi (before hash since both are hex)
    if is_bssid(input_value):
        return ScanType.WIFI.value

    # Check for hash patterns (before email since hashes can contain @)
    hash_type = detect_hash_type(input_value)
    if hash_type:
        return ScanType.HASH.value

    # Check for email
    if is_email(input_value):
        return ScanType.EMAIL.value

    # Check for phone number
    if is_phone_number(input_value):
        return ScanType.PHONE.value

    # Check for domain (before username since domains can look like usernames)
    if is_domain(input_value):
        return ScanType.DOMAIN.value

    # Check for username
    if is_username(input_value):
        return ScanType.USERNAME.value

    # Check for address (most general, check last)
    if is_address(input_value):
        return ScanType.ADDRESS.value

    return None


def is_ip_address(ip_str: str) -> bool:
    """
    Check if string is a valid IP address (IPv4 or IPv6).

    Args:
        ip_str: The string to check

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_email(email_str: str) -> bool:
    """
    Check if string is a valid email address.

    Args:
        email_str: The string to check

    Returns:
        True if valid email, False otherwise
    """
    pattern = re.compile(INPUT_PATTERNS["email"])
    return bool(pattern.match(email_str))


def is_phone_number(phone_str: str) -> bool:
    """
    Check if string appears to be a phone number.

    Args:
        phone_str: The string to check

    Returns:
        True if appears to be phone number, False otherwise
    """
    # Remove common formatting characters for validation
    cleaned = re.sub(r"[^\d+]", "", phone_str)

    # Must have at least 10 digits to be considered a phone number
    if len(cleaned) < 10:
        return False

    # Check pattern
    pattern = re.compile(INPUT_PATTERNS["phone"])
    return bool(pattern.match(phone_str))


def is_username(username_str: str) -> bool:
    """
    Check if string could be a username.

    Args:
        username_str: The string to check

    Returns:
        True if appears to be username, False otherwise
    """
    # Remove @ if present
    username = username_str.lstrip("@")

    # Basic username validation
    if len(username) < 3 or len(username) > 30:
        return False

    # Should contain only alphanumeric characters, underscores, and hyphens
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False

    # Should not be just numbers
    if username.isdigit():
        return False

    return True


def is_address(address_str: str) -> bool:
    """
    Check if string appears to be a physical address.

    Args:
        address_str: The string to check

    Returns:
        True if appears to be address, False otherwise
    """
    # Look for common address patterns
    address_indicators = [
        r"\b\d+\s+[A-Za-z0-9\s]+\b",  # Street number + name
        r"\b(st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|ct|court|ln|lane|way|pl|place)\b",  # Street types
        r"\b(city|town|village)\b",  # City indicators
        r",\s*[A-Za-z\s]+\d{5}?",  # City, state zip pattern
    ]

    address_text = address_str.lower()
    matches = sum(
        1 for pattern in address_indicators if re.search(pattern, address_text)
    )

    # Consider it an address if it matches at least 2 patterns
    return matches >= 2


def is_bssid(bssid_str: str) -> bool:
    """
    Check if string is a valid BSSID (MAC address).

    BSSID formats:
    - AA:BB:CC:DD:EE:FF
    - AA-BB-CC-DD-EE-FF
    - AABBCCDDEEFF (no separator)

    Also checks for BSSID|SSID combined format.

    Args:
        bssid_str: The string to check

    Returns:
        True if valid BSSID, False otherwise
    """
    # Check for BSSID|SSID format
    if "|" in bssid_str:
        bssid_str = bssid_str.split("|")[0].strip()

    # Standard BSSID pattern with colon or dash separators
    pattern = re.compile(INPUT_PATTERNS["bssid"])
    if pattern.match(bssid_str):
        return True

    # Also check for no-separator format (12 hex chars)
    if len(bssid_str) == 12 and re.match(r"^[0-9A-Fa-f]{12}$", bssid_str):
        return True

    return False


def is_domain(domain_str: str) -> bool:
    """
    Check if string is a valid domain name.

    Args:
        domain_str: The string to check

    Returns:
        True if valid domain, False otherwise
    """
    # Must have at least one dot
    if "." not in domain_str:
        return False

    # Should not contain @ (that's an email)
    if "@" in domain_str:
        return False

    # Should not start with a number followed by dots (that might be an IP)
    if re.match(r"^\d+\.\d+", domain_str):
        return False

    # Check domain pattern
    pattern = re.compile(INPUT_PATTERNS["domain"])
    if not pattern.match(domain_str):
        return False

    # Check TLD exists and is valid length (2-10 chars)
    parts = domain_str.split(".")
    tld = parts[-1]
    if len(tld) < 2 or len(tld) > 10:
        return False

    # TLD should be alphabetic
    if not tld.isalpha():
        return False

    return True


def detect_hash_type(hash_str: str) -> Optional[str]:
    """
    Detect the type of hash based on length and pattern.

    Args:
        hash_str: The hash string to analyze

    Returns:
        The detected hash type, or None if not a hash
    """
    hash_str = hash_str.strip().lower()

    # Check MD5
    if len(hash_str) == 32 and re.match(r"^[a-f0-9]+$", hash_str):
        return "MD5"

    # Check SHA1
    if len(hash_str) == 40 and re.match(r"^[a-f0-9]+$", hash_str):
        return "SHA1"

    # Check SHA224
    if len(hash_str) == 56 and re.match(r"^[a-f0-9]+$", hash_str):
        return "SHA224"

    # Check SHA256
    if len(hash_str) == 64 and re.match(r"^[a-f0-9]+$", hash_str):
        return "SHA256"

    # Check SHA384
    if len(hash_str) == 96 and re.match(r"^[a-f0-9]+$", hash_str):
        return "SHA384"

    # Check SHA512
    if len(hash_str) == 128 and re.match(r"^[a-f0-9]+$", hash_str):
        return "SHA512"

    # Check NTLM (same length as MD5 but different format)
    if len(hash_str) == 32 and re.match(r"^[a-f0-9]+$", hash_str):
        # Could be MD5 or NTLM, would need context to differentiate
        return "NTLM"

    # Check MySQL 4.1+ (41 characters, starts with *)
    if (
        len(hash_str) == 41
        and hash_str.startswith("*")
        and re.match(r"^\*[a-f0-9]+$", hash_str)
    ):
        return "MySQL 4.1+"

    # Check bcrypt (60 characters, specific format)
    if len(hash_str) == 60 and re.match(r"^\$2[aby]?\$[0-9]{2}\$", hash_str):
        return "bcrypt"

    # Check Argon2 (variable length, specific format)
    if hash_str.startswith("$argon2"):
        return "Argon2"

    return None


def extract_metadata(input_value: str, input_type: str) -> dict:
    """
    Extract metadata from the input based on its type.

    Args:
        input_value: The input string
        input_type: The detected input type

    Returns:
        Dictionary containing extracted metadata
    """
    metadata = {"original": input_value, "type": input_type, "confidence": 1.0}

    if input_type == ScanType.IP.value:
        try:
            ip_obj = ipaddress.ip_address(input_value)
            metadata.update(
                {
                    "version": "IPv6"
                    if isinstance(ip_obj, ipaddress.IPv6Address)
                    else "IPv4",
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_multicast": ip_obj.is_multicast,
                }
            )
        except ValueError:
            metadata["confidence"] = 0.5

    elif input_type == ScanType.EMAIL.value:
        domain = input_value.split("@")[-1].lower()
        metadata.update(
            {
                "domain": domain,
                "local_part": input_value.split("@")[0],
                "is_common_provider": domain
                in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"],
            }
        )

    elif input_type == ScanType.PHONE.value:
        # Enhanced phone metadata extraction using phonenumbers
        try:
            import phonenumbers

            parsed_number = phonenumbers.parse(input_value, None)

            if phonenumbers.is_valid_number(parsed_number):
                metadata.update(
                    {
                        "country_code": getattr(
                            parsed_number, "country_code", "Unknown"
                        ),
                        "national_number": getattr(parsed_number, "national_number", 0),
                        "is_valid": True,
                        "is_possible": phonenumbers.is_possible_number(parsed_number),
                        "international_format": phonenumbers.format_number(
                            parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                        ),
                        "national_format": phonenumbers.format_number(
                            parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL
                        ),
                        "e164_format": phonenumbers.format_number(
                            parsed_number, phonenumbers.PhoneNumberFormat.E164
                        ),
                    }
                )
            else:
                metadata.update(
                    {
                        "is_valid": False,
                        "is_possible": phonenumbers.is_possible_number(parsed_number)
                        if parsed_number
                        else False,
                    }
                )
        except Exception:
            # Fallback to basic analysis
            pass

    elif input_type == ScanType.WIFI.value:
        # Extract BSSID and optional SSID
        bssid = input_value
        ssid = None

        if "|" in input_value:
            parts = input_value.split("|", 1)
            bssid = parts[0].strip()
            ssid = parts[1].strip() if len(parts) > 1 else None

        # Normalize BSSID format
        bssid = bssid.replace("-", ":").upper()

        # Extract OUI (first 3 octets) for vendor lookup
        oui = ":".join(bssid.split(":")[:3]) if ":" in bssid else bssid[:8]

        metadata.update(
            {
                "bssid": bssid,
                "ssid": ssid,
                "oui": oui,
                "has_ssid": ssid is not None,
            }
        )

    elif input_type == ScanType.DOMAIN.value:
        parts = input_value.lower().split(".")
        tld = parts[-1] if parts else ""
        sld = parts[-2] if len(parts) > 1 else ""

        metadata.update(
            {
                "tld": tld,
                "sld": sld,
                "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else None,
                "level": len(parts),
            }
        )

    return metadata


def validate_input(
    input_value: str, expected_type: Optional[str] = None
) -> Tuple[bool, str, dict]:
    """
    Validate input and optionally check if it matches expected type.

    Args:
        input_value: The input to validate
        expected_type: Expected scan type (optional)

    Returns:
        Tuple of (is_valid, detected_type, metadata)
    """
    if not input_value or not isinstance(input_value, str):
        return False, "none", {}

    detected_type = detect_input_type(input_value)

    if expected_type and detected_type != expected_type:
        return False, detected_type or "none", {}

    if not detected_type:
        return False, "none", {}

    metadata = extract_metadata(input_value, detected_type)

    # Additional validation based on type
    if detected_type == ScanType.EMAIL.value:
        # Additional email validation
        local_part = input_value.split("@")[0]
        if len(local_part) > 64:  # RFC 5321 limit
            return False, detected_type, metadata

    elif detected_type == ScanType.PHONE.value:
        # Additional phone validation using phonenumbers
        try:
            import phonenumbers

            parsed_number = phonenumbers.parse(input_value, None)
            if not phonenumbers.is_valid_number(parsed_number):
                return False, detected_type, metadata
        except Exception:
            # Continue with basic validation if phonenumbers fails
            pass

        digits = re.sub(r"[^\d+]", "", input_value)
        if len(digits) > 15:  # E.164 limit
            return False, detected_type, metadata

    return True, detected_type, metadata
