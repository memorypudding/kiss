"""Platform Check Plugin.

Checks username availability across common platforms.
Fully async implementation with concurrent platform checks for high performance.
"""

import asyncio
from typing import Any, Callable, Dict, List, Tuple

from ..async_base import AsyncBasePlugin, PluginMetadata


class PlatformCheckPlugin(AsyncBasePlugin):
    """Username platform enumeration plugin (async)."""

    # Platform configurations: (name, url_template, check_method)
    PLATFORMS = [
        ("GitHub", "https://github.com/{}", "status_200"),
        ("Twitter/X", "https://twitter.com/{}", "status_200"),
        ("Instagram", "https://instagram.com/{}", "status_200"),
        ("Reddit", "https://reddit.com/user/{}", "status_200"),
        ("LinkedIn", "https://linkedin.com/in/{}", "status_200"),
        ("TikTok", "https://tiktok.com/@{}", "status_200"),
        ("YouTube", "https://youtube.com/@{}", "status_200"),
        ("Pinterest", "https://pinterest.com/{}", "status_200"),
        ("Twitch", "https://twitch.tv/{}", "status_200"),
        ("Steam", "https://steamcommunity.com/id/{}", "status_200"),
        ("Medium", "https://medium.com/@{}", "status_200"),
        ("DevTo", "https://dev.to/{}", "status_200"),
        ("HackerNews", "https://news.ycombinator.com/user?id={}", "status_200"),
        ("Keybase", "https://keybase.io/{}", "status_200"),
        ("Mastodon", "https://mastodon.social/@{}", "status_200"),
        ("GitLab", "https://gitlab.com/{}", "status_200"),
        ("Bitbucket", "https://bitbucket.org/{}/", "status_200"),
        ("Dribbble", "https://dribbble.com/{}", "status_200"),
        ("Behance", "https://behance.net/{}", "status_200"),
        ("Flickr", "https://flickr.com/people/{}", "status_200"),
    ]

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="platform_check",
            display_name="Platform Check",
            description="Check username across social platforms (async concurrent)",
            version="2.0.0",
            category="Username Enumeration",
            supported_scan_types=["USERNAME"],
            api_key_requirements=[],  # No API key required
            rate_limit=30,  # Be respectful to platforms
            timeout=10,
            author="KISS Team",
        )

    async def scan_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute concurrent username platform checks."""
        results: List[Dict[str, Any]] = []
        progress_callback(0.1)

        # Clean username
        username = target.lstrip("@").strip()

        if not username:
            results.append(
                self._create_result(
                    "Validation",
                    "Invalid username",
                    threat_level="HIGH",
                )
            )
            return results

        results.append(
            self._create_result(
                "Username",
                username,
            )
        )

        progress_callback(0.2)

        # Create tasks for all platform checks
        tasks = []
        for platform_name, url_template, check_method in self.PLATFORMS:
            url = url_template.format(username)
            task = self._check_platform_async(platform_name, url, check_method)
            tasks.append(task)

        # Execute all checks concurrently
        platform_results = await asyncio.gather(*tasks, return_exceptions=True)

        progress_callback(0.8)

        # Process results
        found_platforms = []
        not_found_platforms = []

        for i, result in enumerate(platform_results):
            platform_name = self.PLATFORMS[i][0]

            if isinstance(result, Exception):
                # Skip failed checks
                continue

            found, url = result
            if found:
                found_platforms.append((platform_name, url))
            else:
                not_found_platforms.append(platform_name)

        # Add found platforms
        if found_platforms:
            platform_names = [p[0] for p in found_platforms]
            results.append(
                self._create_result(
                    "Profiles Found",
                    f"{len(found_platforms)} platform(s): {', '.join(platform_names)}",
                    threat_level="MEDIUM" if len(found_platforms) > 5 else None,
                    metadata={"count": len(found_platforms)},
                )
            )

            # Add individual results
            for platform_name, url in found_platforms:
                results.append(
                    self._create_result(
                        f"Found: {platform_name}",
                        url,
                        metadata={"platform": platform_name, "url": url},
                    )
                )
        else:
            results.append(
                self._create_result(
                    "Profiles Found",
                    "No profiles found on checked platforms",
                )
            )

        # Summary of not found
        if not_found_platforms:
            results.append(
                self._create_result(
                    "Not Found On",
                    f"{len(not_found_platforms)} platform(s)",
                    metadata={"platforms": not_found_platforms},
                )
            )

        progress_callback(1.0)
        return results

    async def _check_platform_async(
        self, platform_name: str, url: str, check_method: str
    ) -> Tuple[bool, str]:
        """Check if username exists on a platform asynchronously.

        Args:
            platform_name: Name of the platform
            url: URL to check
            check_method: Method to use for checking

        Returns:
            Tuple of (found, url)
        """
        try:
            # Use HEAD request for faster checking
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
            }

            async with self.session.head(
                url,
                headers=headers,
                timeout=self.metadata.timeout,
                allow_redirects=True,
            ) as response:
                if check_method == "status_200":
                    # Check if response is 200 OK
                    found = response.status == 200
                    return (found, url)

        except asyncio.TimeoutError:
            # Timeout - assume not found
            return (False, url)

        except Exception:
            # Error - assume not found
            return (False, url)

        return (False, url)
