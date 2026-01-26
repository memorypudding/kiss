"""KISS Query Parser.

Implements a strict query parser for structured OSINT queries.
Supports field:"value" syntax for targeted searches.

Query Syntax:
    - Simple targets: user@example.com, 192.168.1.1, +1234567890
    - Structured queries: email:"user@example.com" ip:"8.8.8.8"
    - Combined queries: name:"John Doe" location:"New York"
    - WiFi queries: bssid:"AA:BB:CC:DD:EE:FF" ssid:"MyNetwork"
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .constants import INPUT_PATTERNS


@dataclass
class ParsedQuery:
    """Represents a parsed query with extracted fields."""

    raw_query: str
    query_type: str  # "simple" or "structured"
    scan_type: Optional[str] = None
    primary_target: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    is_valid: bool = True

    def __str__(self) -> str:
        if self.query_type == "simple":
            return f"Simple query: {self.primary_target} (type: {self.scan_type})"
        else:
            field_str = ", ".join(f'{k}="{v}"' for k, v in self.fields.items())
            return f"Structured query: {field_str} (type: {self.scan_type})"


class QueryParser:
    """Parser for KISS query syntax.

    Supports both simple targets and structured field:value queries.
    """

    # Supported query fields with their associated scan types
    FIELD_SCAN_TYPES = {
        "email": "EMAIL",
        "mail": "EMAIL",
        "e-mail": "EMAIL",
        "ip": "IP",
        "ipv4": "IP",
        "ipv6": "IP",
        "address": "ADDRESS",
        "addr": "ADDRESS",
        "location": "ADDRESS",
        "phone": "PHONE",
        "tel": "PHONE",
        "mobile": "PHONE",
        "username": "USERNAME",
        "user": "USERNAME",
        "handle": "USERNAME",
        "hash": "HASH",
        "password": "HASH",
        "pwd": "HASH",
        "domain": "DOMAIN",
        "bssid": "WIFI",
        "ssid": "WIFI",
        "wifi": "WIFI",
        "mac": "WIFI",
        "name": "NAME",  # Future support
    }

    # Validation patterns for fields
    FIELD_VALIDATORS = {
        "email": re.compile(INPUT_PATTERNS["email"]),
        "ip": re.compile(INPUT_PATTERNS["ip"]),
        "phone": re.compile(INPUT_PATTERNS["phone"]),
        "bssid": re.compile(INPUT_PATTERNS["bssid"]),
        "hash": re.compile(r"^[a-fA-F0-9]{32,128}$|^\$2[aby]?\$.+|^\$argon2"),
        "domain": re.compile(INPUT_PATTERNS["domain"]),
    }

    def __init__(self):
        """Initialize the query parser."""
        # Regex for field:"value" or field:value patterns
        self.field_pattern = re.compile(
            r'(\w+):\s*(?:"([^"]+)"|\'([^\']+)\'|(\S+))'
        )

    def parse(self, query: str) -> ParsedQuery:
        """Parse a query string.

        Args:
            query: Raw query string

        Returns:
            ParsedQuery object with extracted information
        """
        query = query.strip()

        if not query:
            return ParsedQuery(
                raw_query=query,
                query_type="simple",
                is_valid=False,
                errors=["Empty query"],
            )

        # Check if this is a structured query (contains field:value patterns)
        if self._is_structured_query(query):
            return self._parse_structured(query)
        else:
            return self._parse_simple(query)

    def _is_structured_query(self, query: str) -> bool:
        """Check if query uses structured field:value syntax."""
        # First, check if this looks like a BSSID (MAC address)
        # BSSIDs look like AA:BB:CC:DD:EE:FF and would incorrectly match field:value
        if re.match(INPUT_PATTERNS["bssid"], query.strip()):
            return False

        # Also check for BSSID with alternate separator
        if re.match(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$", query.strip()):
            return False

        # Check for BSSID|SSID format
        if "|" in query:
            parts = query.split("|", 1)
            if re.match(INPUT_PATTERNS["bssid"], parts[0].strip()):
                return False

        # Look for field:value pattern - must be a known field name
        match = self.field_pattern.search(query)
        if match:
            field_name = match.group(1).lower()
            # Only consider it structured if the field name is recognized
            return field_name in self.FIELD_SCAN_TYPES

        return False

    def _parse_simple(self, query: str) -> ParsedQuery:
        """Parse a simple query (just a target value)."""
        result = ParsedQuery(
            raw_query=query,
            query_type="simple",
            primary_target=query,
        )

        # Auto-detect the type
        scan_type = self._detect_type(query)
        result.scan_type = scan_type

        if not scan_type:
            result.errors.append(f"Could not determine query type for: {query}")
            result.is_valid = False

        return result

    def _parse_structured(self, query: str) -> ParsedQuery:
        """Parse a structured query with field:value pairs."""
        result = ParsedQuery(
            raw_query=query,
            query_type="structured",
        )

        # Extract all field:value pairs
        matches = self.field_pattern.findall(query)

        if not matches:
            result.errors.append("No valid field:value pairs found")
            result.is_valid = False
            return result

        scan_types_found = set()

        for match in matches:
            field_name = match[0].lower()
            # Value is in group 2 (double quoted), 3 (single quoted), or 4 (unquoted)
            value = match[1] or match[2] or match[3]

            if not value:
                result.errors.append(f"Empty value for field: {field_name}")
                continue

            # Map field name to canonical form
            if field_name in self.FIELD_SCAN_TYPES:
                scan_type = self.FIELD_SCAN_TYPES[field_name]
                scan_types_found.add(scan_type)

                # Store field value
                result.fields[field_name] = value

                # Validate field value if validator exists
                canonical_field = self._get_canonical_field(field_name)
                if canonical_field in self.FIELD_VALIDATORS:
                    validator = self.FIELD_VALIDATORS[canonical_field]
                    if not validator.match(value):
                        result.errors.append(
                            f"Invalid format for {field_name}: {value}"
                        )
            else:
                result.errors.append(f"Unknown field: {field_name}")

        # Determine primary scan type
        if scan_types_found:
            # Priority order for scan types
            priority = ["EMAIL", "IP", "PHONE", "WIFI", "USERNAME", "ADDRESS", "HASH", "DOMAIN", "NAME"]
            for ptype in priority:
                if ptype in scan_types_found:
                    result.scan_type = ptype
                    break

            # Set primary target based on scan type
            result.primary_target = self._get_primary_target(result)

        if result.errors:
            result.is_valid = False

        return result

    def _get_canonical_field(self, field_name: str) -> str:
        """Get canonical field name for validation."""
        field_mapping = {
            "mail": "email",
            "e-mail": "email",
            "ipv4": "ip",
            "ipv6": "ip",
            "addr": "address",
            "location": "address",
            "tel": "phone",
            "mobile": "phone",
            "user": "username",
            "handle": "username",
            "password": "hash",
            "pwd": "hash",
            "wifi": "bssid",
            "mac": "bssid",
        }
        return field_mapping.get(field_name, field_name)

    def _get_primary_target(self, parsed: ParsedQuery) -> str:
        """Get the primary target value from parsed query."""
        # Map scan type to primary field
        type_to_field = {
            "EMAIL": ["email", "mail", "e-mail"],
            "IP": ["ip", "ipv4", "ipv6"],
            "PHONE": ["phone", "tel", "mobile"],
            "USERNAME": ["username", "user", "handle"],
            "ADDRESS": ["address", "addr", "location"],
            "HASH": ["hash", "password", "pwd"],
            "DOMAIN": ["domain"],
            "WIFI": ["bssid", "ssid", "wifi", "mac"],
            "NAME": ["name"],
        }

        if parsed.scan_type in type_to_field:
            for field in type_to_field[parsed.scan_type]:
                if field in parsed.fields:
                    return parsed.fields[field]

        # Return first field value as fallback
        if parsed.fields:
            return list(parsed.fields.values())[0]

        return ""

    def _detect_type(self, target: str) -> Optional[str]:
        """Auto-detect the type of a simple query target."""
        target = target.strip()

        # Check for email
        if re.match(INPUT_PATTERNS["email"], target):
            return "EMAIL"

        # Check for IP
        if re.match(INPUT_PATTERNS["ip"], target):
            return "IP"

        # Check for phone (starts with + or has 10+ digits)
        if re.match(INPUT_PATTERNS["phone"], target):
            return "PHONE"

        # Check for BSSID (including BSSID|SSID format)
        if re.match(INPUT_PATTERNS["bssid"], target):
            return "WIFI"

        # Check for BSSID|SSID combined format
        if "|" in target:
            parts = target.split("|", 1)
            if re.match(INPUT_PATTERNS["bssid"], parts[0].strip()):
                return "WIFI"

        # Check for hash (hex string of common lengths)
        if re.match(r"^[a-fA-F0-9]{32}$", target):  # MD5
            return "HASH"
        if re.match(r"^[a-fA-F0-9]{40}$", target):  # SHA1
            return "HASH"
        if re.match(r"^[a-fA-F0-9]{64}$", target):  # SHA256
            return "HASH"
        if re.match(r"^\$2[aby]?\$", target):  # bcrypt
            return "HASH"

        # Check for username (starts with @)
        if target.startswith("@"):
            return "USERNAME"

        # Check for address (quoted string or contains commas)
        if target.startswith('"') and target.endswith('"'):
            return "ADDRESS"
        if "," in target and len(target) > 20:
            return "ADDRESS"

        # Check for domain
        if re.match(INPUT_PATTERNS["domain"], target) and "." in target:
            # Avoid matching single words
            if not "@" in target and not target[0].isdigit():
                return "DOMAIN"

        # Default to username for short alphanumeric strings
        if re.match(r"^[\w\-\.]{3,30}$", target):
            return "USERNAME"

        return None

    def get_wifi_components(self, parsed: ParsedQuery) -> Tuple[Optional[str], Optional[str]]:
        """Extract BSSID and SSID from a WiFi query.

        Args:
            parsed: ParsedQuery object

        Returns:
            Tuple of (bssid, ssid)
        """
        bssid = None
        ssid = None

        if parsed.query_type == "structured":
            bssid = parsed.fields.get("bssid") or parsed.fields.get("mac") or parsed.fields.get("wifi")
            ssid = parsed.fields.get("ssid")
        else:
            # Simple query - check if it's a BSSID
            if parsed.scan_type == "WIFI":
                target = parsed.primary_target

                # Check for BSSID|SSID format
                if "|" in target:
                    parts = target.split("|", 1)
                    bssid = parts[0].strip()
                    ssid = parts[1].strip() if len(parts) > 1 else None
                elif re.match(INPUT_PATTERNS["bssid"], target):
                    bssid = target
                else:
                    # Assume it's an SSID
                    ssid = target

        # Normalize BSSID format
        if bssid:
            bssid = bssid.replace("-", ":").upper()

        return bssid, ssid

    def format_for_display(self, parsed: ParsedQuery) -> str:
        """Format parsed query for display in TUI.

        Args:
            parsed: ParsedQuery object

        Returns:
            Formatted string for display
        """
        if not parsed.is_valid:
            return f"Invalid query: {', '.join(parsed.errors)}"

        if parsed.query_type == "simple":
            return f"{parsed.scan_type}: {parsed.primary_target}"
        else:
            parts = []
            for field, value in parsed.fields.items():
                parts.append(f'{field}:"{value}"')
            return " ".join(parts)


# Global parser instance
_parser: Optional[QueryParser] = None


def get_parser() -> QueryParser:
    """Get the global query parser instance."""
    global _parser
    if _parser is None:
        _parser = QueryParser()
    return _parser


def parse_query(query: str) -> ParsedQuery:
    """Parse a query string using the global parser.

    Args:
        query: Raw query string

    Returns:
        ParsedQuery object
    """
    return get_parser().parse(query)
