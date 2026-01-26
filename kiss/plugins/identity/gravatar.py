"""Gravatar Plugin.

Looks up profile information from Gravatar.
Fully async implementation for high-performance scanning.
"""

import hashlib
from typing import Any, Callable, Dict, List

from ..async_base import AsyncBasePlugin, PluginMetadata


class GravatarPlugin(AsyncBasePlugin):
    """Gravatar profile lookup plugin (async)."""

    BASE_URL = "https://en.gravatar.com"

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="gravatar",
            display_name="Gravatar",
            description="Email profile lookup via Gravatar",
            version="2.0.0",
            category="Identity Lookup",
            supported_scan_types=["EMAIL"],
            api_key_requirements=[],  # No API key required
            rate_limit=60,
            timeout=15,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute Gravatar lookup asynchronously."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.2)

        # Create email hash
        email_hash = hashlib.md5(target.lower().strip().encode()).hexdigest()

        url = f"{self.BASE_URL}/{email_hash}.json"

        try:
            await self._rate_limit()

            async with self.session.get(
                url,
                timeout=self.metadata.timeout,
            ) as response:
                progress_callback(0.6)

                if response.status == 200:
                    data = await response.json()
                    entry = data.get("entry", [{}])[0]

                    # Display name
                    display_name = entry.get("displayName", "")
                    if display_name:
                        results.append(
                            self._create_result(
                                "Gravatar Name",
                                display_name,
                            )
                        )

                    # Preferred username
                    preferred_username = entry.get("preferredUsername", "")
                    if preferred_username and preferred_username != display_name:
                        results.append(
                            self._create_result(
                                "Username",
                                preferred_username,
                            )
                        )

                    # About/bio
                    about = entry.get("aboutMe", "")
                    if about:
                        # Truncate long bios
                        about_text = about[:100] + "..." if len(about) > 100 else about
                        results.append(
                            self._create_result(
                                "About",
                                about_text,
                                metadata={"full_about": about},
                            )
                        )

                    # Location
                    location = entry.get("currentLocation", "")
                    if location:
                        results.append(
                            self._create_result(
                                "Location",
                                location,
                            )
                        )

                    # Profile URL
                    profile_url = entry.get("profileUrl", "")
                    if profile_url:
                        results.append(
                            self._create_result(
                                "Profile URL",
                                profile_url,
                            )
                        )

                    # Thumbnail URL
                    thumbnail_url = entry.get("thumbnailUrl", "")
                    if thumbnail_url:
                        results.append(
                            self._create_result(
                                "Avatar URL",
                                thumbnail_url,
                            )
                        )

                    # Linked accounts
                    accounts = entry.get("accounts", [])
                    if accounts:
                        account_names = [
                            a.get("shortname", a.get("domain", "unknown"))
                            for a in accounts[:5]
                        ]
                        results.append(
                            self._create_result(
                                "Linked Accounts",
                                ", ".join(account_names),
                                metadata={"account_count": len(accounts)},
                            )
                        )

                        # Add individual account details
                        for account in accounts[:5]:
                            shortname = account.get("shortname", "")
                            username = account.get("username", "")
                            url = account.get("url", "")
                            verified = account.get("verified", False)

                            if shortname and (username or url):
                                value = username if username else url
                                if verified:
                                    value += " (verified)"

                                results.append(
                                    self._create_result(
                                        f"Account: {shortname.title()}",
                                        value,
                                        metadata={
                                            "platform": shortname,
                                            "username": username,
                                            "url": url,
                                            "verified": verified,
                                        },
                                    )
                                )

                    # Photos
                    photos = entry.get("photos", [])
                    if photos:
                        results.append(
                            self._create_result(
                                "Profile Photos",
                                f"{len(photos)} photo(s) found",
                                metadata={"photo_count": len(photos)},
                            )
                        )

                    # URLs/websites
                    urls = entry.get("urls", [])
                    if urls:
                        for url_entry in urls[:3]:
                            title = url_entry.get("title", "Website")
                            url_value = url_entry.get("value", "")
                            if url_value:
                                results.append(
                                    self._create_result(
                                        f"Website: {title}",
                                        url_value,
                                    )
                                )

                    # Emails (additional emails)
                    emails = entry.get("emails", [])
                    if emails:
                        for email_entry in emails[:3]:
                            email_value = email_entry.get("value", "")
                            primary = email_entry.get("primary", False)
                            if email_value and email_value.lower() != target.lower():
                                label = "Primary Email" if primary else "Additional Email"
                                results.append(
                                    self._create_result(
                                        label,
                                        email_value,
                                    )
                                )

                    # If we got profile data but no results, note that
                    if not results:
                        results.append(
                            self._create_result(
                                "Gravatar",
                                "Profile exists but no public data",
                            )
                        )

                elif response.status == 404:
                    results.append(
                        self._create_result(
                            "Gravatar",
                            "No profile found",
                        )
                    )

        except Exception as e:
            results.append(
                self._create_result(
                    "Gravatar Error",
                    f"Lookup failed: {str(e)}",
                    threat_level="LOW",
                )
            )

        progress_callback(1.0)
        return results
