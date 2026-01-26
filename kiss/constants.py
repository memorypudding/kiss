"""XSINT Constants Module.

Defines constants, enums, and configuration values used throughout the KISS application.
"""

from enum import Enum
from typing import Literal


class ScanType(Enum):
    """Enumeration of supported scan types."""

    IP = "IP"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    DOMAIN = "DOMAIN"
    USERNAME = "USERNAME"
    ADDRESS = "ADDRESS"
    HASH = "HASH"
    PASSWORD = "PASSWORD"
    WIFI = "WIFI"


class ScanStatus(Enum):
    """Enumeration of scan status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ThreatLevel(Enum):
    """Enumeration of threat levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Default configuration values
DEFAULT_CONFIG = {
    "max_concurrent_scans": 5,
    "request_timeout": 30,
    "rate_limit_delay": 1.0,
    "max_retries": 3,
    "cache_duration": 3600,  # 1 hour
    "log_level": "INFO",
    "enable_animations": True,
    "default_theme": "Ocean",
}

# API endpoints
API_ENDPOINTS = {
    "HIBP_API": "https://haveibeenpwned.com/api/v3",
    "IPINFO_API": "https://ipinfo.io",
    "GRATAR_API": "https://en.gravatar.com",
    "NOMINATIM_API": "https://nominatim.openstreetmap.org",
    "HUDSON_ROCK_API": "https://api.hudsonrock.com/api/json/v2/stealer-info",
    "GOOGLE_GEOLOCATION_API": "https://www.googleapis.com/geolocation/v1/geolocate",
    "WIGLE_API": "https://api.wigle.net/api/v2",
}

# Request headers
REQUEST_HEADERS = {
    "User-Agent": "KISS/2.0 (OSINT Tool)",
    "Accept": "application/json",
    "Accept-Encoding": "gzip, deflate",
}

# Rate limits (requests per minute)
RATE_LIMITS = {
    "HIBP": 120,  # Official HIBP limit
    "IPINFO": 1000,
    "GRATAR": 60,
    "NOMINATIM": 60,
    "DEFAULT": 30,
}

# Input validation patterns
INPUT_PATTERNS = {
    "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "phone": r"^\+?[\d\s\-\(\)]{10,}$",
    "ip": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    "domain": r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$",  # noqa: E501
    "hash_md5": r"^[a-fA-F0-9]{32}$",
    "hash_sha1": r"^[a-fA-F0-9]{40}$",
    "hash_sha256": r"^[a-fA-F0-9]{64}$",
    "hash_sha512": r"^[a-fA-F0-9]{128}$",
    # BSSID format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    "bssid": r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
    # SSID: 1-32 characters (printable ASCII or UTF-8)
    "ssid": r"^.{1,32}$",
}

# Color scheme definitions
THEME_COLORS = {
    "Pastel": [231, 225, 219, 213, 159, 123, 117, 120, 157, 229, 223, 224, 217],
    "Matrix": [46, 47, 48, 49, 50, 51, 82, 83, 84, 85, 86, 87, 118, 119, 120, 121],
    "Ocean": [27, 33, 39, 45, 51, 81, 87, 123, 159, 195],
    "Fire": [196, 202, 208, 214, 220, 226, 227, 228, 229],
    "Monochrome": [0, 7, 8, 15, 16, 241, 248, 252, 255],
}

# Error messages
ERROR_MESSAGES = {
    "invalid_input": "Invalid input format provided",
    "network_error": "Network connection failed",
    "api_error": "API request failed",
    "rate_limit": "Rate limit exceeded, please try again later",
    "invalid_target": "Invalid target for this scan type",
    "permission_denied": "Permission denied for this operation",
    "not_found": "No results found",
    "timeout": "Request timeout",
}

# Success messages
SUCCESS_MESSAGES = {
    "scan_completed": "Scan completed successfully",
    "data_found": "Data found and processed",
    "export_complete": "Export completed successfully",
    "config_saved": "Configuration saved successfully",
}

# File paths and directories
DEFAULT_DIRS = {
    "config": "~/.xsint",
    "cache": "~/.xsint/cache",
    "logs": "~/.xsint/logs",
    "exports": "~/.xsint/exports",
}

# Export formats
EXPORT_FORMATS = [
    "json",
    "csv",
    "xml",
    "txt",
    "html",
    "pdf",
]

# Supported platforms for username enumeration
SUPPORTED_PLATFORMS = [
    "github",
    "reddit",
    "twitter",
    "instagram",
    "linkedin",
    "facebook",
    "youtube",
    "tiktok",
    "steam",
    "discord",
]

# Database types for hash scanning
HASH_TYPES = Literal[
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "NTLM",
    "MySQL 4.1+",
    "bcrypt",
    "Argon2",
    "PBKDF2-SHA256",
    "Django PBKDF2",
    "MD5 Crypt",
    "SHA256 Crypt",
    "SHA512 Crypt",
    "LM Hash",
    "Cisco Type 5",
    "Cisco Type 7",
]
