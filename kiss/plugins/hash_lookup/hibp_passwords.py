"""HIBP Passwords Plugin.

Checks password hashes against the Have I Been Pwned Passwords database
using the k-anonymity model.
Fully async implementation for high-performance scanning.
"""

import hashlib
from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata


class HIBPPasswordsPlugin(AsyncBasePlugin):
    """HIBP Passwords plugin using k-anonymity (async)."""

    BASE_URL = "https://api.pwnedpasswords.com/range"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="hibp_passwords",
            display_name="HIBP Passwords",
            description="Check password hashes against HIBP database",
            version="2.0.0",
            category="Hash Lookup",
            supported_scan_types=["HASH"],
            api_key_requirements=[],  # No API key required (k-anonymity)
            rate_limit=100,
            timeout=15,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute password hash check asynchronously."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.2)

        # Determine hash type and get SHA1
        sha1_hash = self._get_sha1_hash(target)

        if not sha1_hash:
            results.append(
                self._create_result(
                    "Password Check",
                    "Invalid hash format",
                    threat_level="LOW",
                )
            )
            progress_callback(1.0)
            return results

        # Use k-anonymity - only send first 5 chars
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.BASE_URL}/{prefix}"

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.6)

                if response.status == 200:
                    text = await response.text()

                    # Search for our suffix in the response
                    found = False
                    count = 0

                    for line in text.splitlines():
                        parts = line.strip().split(":")
                        if len(parts) == 2:
                            hash_suffix, occurrences = parts
                            if hash_suffix.upper() == suffix.upper():
                                found = True
                                count = int(occurrences)
                                break

                    if found:
                        results.append(
                            self._create_result(
                                "Password Breach",
                                f"PWNED - Found {count:,} times in breaches",
                                threat_level="CRITICAL",
                                metadata={"occurrences": count},
                            )
                        )

                        # Add context based on count
                        if count > 1000000:
                            results.append(
                                self._create_result(
                                    "Risk Level",
                                    "Extremely common password - do not use",
                                    threat_level="CRITICAL",
                                )
                            )
                        elif count > 100000:
                            results.append(
                                self._create_result(
                                    "Risk Level",
                                    "Very common password - high risk",
                                    threat_level="HIGH",
                                )
                            )
                        elif count > 1000:
                            results.append(
                                self._create_result(
                                    "Risk Level",
                                    "Common password - moderate risk",
                                    threat_level="MEDIUM",
                                )
                            )
                        else:
                            results.append(
                                self._create_result(
                                    "Risk Level",
                                    "Less common but still exposed",
                                    threat_level="MEDIUM",
                                )
                            )
                    else:
                        results.append(
                            self._create_result(
                                "Password Breach",
                                "Not found in known breaches",
                            )
                        )

                else:
                    results.append(
                        self._create_result(
                            "Password Check",
                            f"Service error: HTTP {response.status}",
                            threat_level="LOW",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Password Check Error",
                    f"Request failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        # Add hash info
        results.append(
            self._create_result(
                "Hash Type",
                self._detect_hash_type(target),
            )
        )

        progress_callback(1.0)
        return results

    def _get_sha1_hash(self, input_hash: str) -> str:
        """Convert input to SHA1 hash for HIBP lookup.

        Args:
            input_hash: Input hash string

        Returns:
            SHA1 hash in uppercase
        """
        input_hash = input_hash.strip()

        # If already SHA1 (40 hex chars), use directly
        if len(input_hash) == 40 and all(c in "0123456789abcdefABCDEF" for c in input_hash):
            return input_hash.upper()

        # If MD5 (32 hex chars), we can't convert - hash the MD5 as if it were a password
        if len(input_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in input_hash):
            # Hash the MD5 string itself
            return hashlib.sha1(input_hash.encode()).hexdigest().upper()

        # For other lengths, assume it might be plaintext and hash it
        if len(input_hash) < 32:
            return hashlib.sha1(input_hash.encode()).hexdigest().upper()

        # For SHA256 (64 chars) or longer, hash the hash string
        if len(input_hash) >= 64 and all(c in "0123456789abcdefABCDEF" for c in input_hash):
            return hashlib.sha1(input_hash.encode()).hexdigest().upper()

        return ""

    def _detect_hash_type(self, input_hash: str) -> str:
        """Detect the type of hash.

        Args:
            input_hash: Hash string to analyze

        Returns:
            Detected hash type name
        """
        input_hash = input_hash.strip().lower()
        length = len(input_hash)

        # Check if all hex characters
        is_hex = all(c in "0123456789abcdef" for c in input_hash)

        if not is_hex:
            # Check for bcrypt
            if input_hash.startswith("$2") and len(input_hash) == 60:
                return "bcrypt"
            # Check for Argon2
            if input_hash.startswith("$argon2"):
                return "Argon2"
            return "Unknown/Plaintext"

        # Hex-based hashes
        hash_types = {
            32: "MD5/NTLM",
            40: "SHA1",
            56: "SHA224",
            64: "SHA256",
            96: "SHA384",
            128: "SHA512",
        }

        return hash_types.get(length, f"Unknown ({length} chars)")
