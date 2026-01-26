"""Async KISS OSINT Engine.

Main async engine for orchestrating OSINT scans across multiple services.
Uses the async plugin system for high-performance concurrent scanning.
Integrates with the query parser for structured query support.
"""

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import aiohttp

from kiss.config import get_config
from kiss.constants import ScanStatus, ScanType
from kiss.models import ScanResult, ThreatLevel
from kiss.scanner.detectors import detect_input_type, extract_metadata
from kiss.query_parser import ParsedQuery, parse_query, get_parser
from kiss.utils.logging import get_logger

logger = get_logger(__name__)


class AsyncOSINTEngine:
    """Main async OSINT scanning engine with plugin support.

    Benefits over sync engine:
    - Non-blocking HTTP requests
    - Higher concurrency with hundreds of modules
    - Better resource utilization
    - Faster overall scan times
    - Configurable concurrency limits
    """

    def __init__(self, max_concurrent_requests: int = 100):
        """Initialize the async OSINT engine.

        Args:
            max_concurrent_requests: Maximum concurrent HTTP requests
        """
        self.config = get_config()
        self.max_concurrent_requests = max_concurrent_requests

        # Create shared session with connection pooling
        self.session = aiohttp.ClientSession(
            headers={
                "User-Agent": "KISS/2.0 (OSINT Tool)",
                "Accept": "application/json",
            },
            connector=aiohttp.TCPConnector(
                limit=max_concurrent_requests,
                limit_per_host=20,
                ttl_dns_cache=300,
                use_dns_cache=True,
            ),
            timeout=aiohttp.ClientTimeout(total=30),
        )

        # Create semaphore for rate limiting
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)

        # Plugin management
        self._plugin_instances: Dict[str, Any] = {}
        self._registry = None
        self._plugins_initialized = False

    async def _init_plugins(self):
        """Initialize the plugin system asynchronously."""
        if self._plugins_initialized:
            return

        try:
            from kiss.plugins.registry import get_registry

            self._registry = get_registry()
            await self._registry.discover_plugins_async()
            self._plugins_initialized = True
        except Exception as e:
            logger.warning(f"Failed to initialize plugins: {e}")
            self._plugins_initialized = True  # Don't retry

    async def _get_plugin_instance(self, plugin_class):
        """Get or create an async plugin instance."""
        name = plugin_class.get_metadata().name
        if name not in self._plugin_instances:
            # Import async base plugin
            from kiss.plugins.async_base import AsyncBasePlugin

            # Check if plugin is already async
            if issubclass(plugin_class, AsyncBasePlugin):
                self._plugin_instances[name] = plugin_class(
                    self.config, self.session, self.semaphore
                )
            else:
                # Wrap sync plugin for async compatibility
                self._plugin_instances[name] = AsyncPluginWrapper(
                    plugin_class, self.config, self.session, self.semaphore
                )
        return self._plugin_instances[name]

    def detect_input_type(self, target: str) -> Optional[str]:
        """Detect the type of input target."""
        return detect_input_type(target)

    def parse_query(self, query: str) -> ParsedQuery:
        """Parse a query string using the query parser.

        Supports both simple targets and structured field:value syntax.

        Args:
            query: Raw query string (e.g., "user@example.com" or 'email:"test@example.com"')

        Returns:
            ParsedQuery object with extracted information
        """
        return parse_query(query)

    def get_wifi_components(self, parsed: ParsedQuery) -> Tuple[Optional[str], Optional[str]]:
        """Extract BSSID and SSID from a parsed WiFi query.

        Args:
            parsed: ParsedQuery object

        Returns:
            Tuple of (bssid, ssid)
        """
        return get_parser().get_wifi_components(parsed)

    async def _scan_with_plugins_async(
        self,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
    ) -> List[Dict[str, Any]]:
        """Execute scan using all applicable plugins concurrently.

        Args:
            target: The target to scan
            scan_type: The type of scan (IP, EMAIL, etc.)
            progress_callback: Progress callback function

        Returns:
            List of result dicts from all plugins
        """
        await self._init_plugins()

        if not self._registry:
            return []

        # Get applicable plugins
        plugins = self._registry.get_by_scan_type(scan_type)

        # Filter to enabled plugins
        enabled_plugins = []
        for plugin_class in plugins:
            plugin_name = plugin_class.get_metadata().name
            if self.config.is_service_enabled(plugin_name):
                enabled_plugins.append(plugin_class)

        if not enabled_plugins:
            return []

        # Create async tasks for all plugins
        tasks = []
        total = len(enabled_plugins)

        for i, plugin_class in enumerate(enabled_plugins):
            task = self._scan_single_plugin_async(
                plugin_class, target, scan_type, progress_callback, i, total
            )
            tasks.append(task)

        # Execute all plugins concurrently
        results_lists = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten results and handle exceptions
        all_results = []
        for i, results in enumerate(results_lists):
            if isinstance(results, Exception):
                plugin_name = enabled_plugins[i].get_metadata().name
                logger.error(f"Plugin {plugin_name} failed: {results}")
            else:
                all_results.extend(results)

        return all_results

    async def _scan_single_plugin_async(
        self,
        plugin_class,
        target: str,
        scan_type: str,
        progress_callback: Callable[[float], None],
        index: int,
        total: int,
    ) -> List[Dict[str, Any]]:
        """Execute a single plugin scan with progress tracking."""
        try:
            plugin = await self._get_plugin_instance(plugin_class)

            # Create sub-progress callback
            def sub_progress(val, idx=index, tot=total):
                overall = (idx + val) / tot
                progress_callback(overall)

            # Check if plugin supports async
            if hasattr(plugin, "scan_async"):
                plugin_results = await plugin.scan_async(
                    target, scan_type, sub_progress
                )
            else:
                # Fallback to sync method
                plugin_results = plugin.scan(target, scan_type, sub_progress)

            return plugin_results

        except Exception as e:
            plugin_name = plugin_class.get_metadata().name
            logger.debug(f"Plugin {plugin_name} failed: {e}")
            return []

    # === Async Scan Methods ===

    async def scan_ip_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async IP address scanning."""
        result = ScanResult(
            scan_type=ScanType.IP,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            # Use async plugin system
            plugin_results = await self._scan_with_plugins_async(
                target, "IP", progress_callback
            )
            for row in plugin_results:
                # Convert threat_level string to enum if needed
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            # Add metadata
            metadata = extract_metadata(target, ScanType.IP.value)
            if metadata.get("is_private"):
                result.add_info(
                    "Network Type", "Private/Internal IP", source="Analysis"
                )
            else:
                result.add_info("Network Type", "Public IP", source="Analysis")

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"IP scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_email_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async email address scanning."""
        result = ScanResult(
            scan_type=ScanType.EMAIL,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            plugin_results = await self._scan_with_plugins_async(
                target, "EMAIL", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            # Add metadata
            metadata = extract_metadata(target, ScanType.EMAIL.value)
            result.add_info(
                "Domain", metadata.get("domain", "unknown"), source="Analysis"
            )
            if metadata.get("is_common_provider"):
                result.add_info(
                    "Provider Type", "Common Email Provider", source="Analysis"
                )

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Email scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_phone_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async phone number scanning."""
        result = ScanResult(
            scan_type=ScanType.PHONE,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            plugin_results = await self._scan_with_plugins_async(
                target, "PHONE", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Phone scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_username_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async username scanning."""
        result = ScanResult(
            scan_type=ScanType.USERNAME,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            # Clean username
            username = target.lstrip("@")

            plugin_results = await self._scan_with_plugins_async(
                username, "USERNAME", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Username scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_address_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async address scanning."""
        result = ScanResult(
            scan_type=ScanType.ADDRESS,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            plugin_results = await self._scan_with_plugins_async(
                target, "ADDRESS", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Address scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_hash_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async hash scanning."""
        result = ScanResult(
            scan_type=ScanType.HASH,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            plugin_results = await self._scan_with_plugins_async(
                target, "HASH", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Hash scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_wifi_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async WiFi (BSSID/SSID) scanning.

        Supports multiple input formats:
        - Simple BSSID: AA:BB:CC:DD:EE:FF
        - BSSID|SSID format: AA:BB:CC:DD:EE:FF|NetworkName
        - Structured query: bssid:"AA:BB:CC:DD:EE:FF" ssid:"NetworkName"
        """
        result = ScanResult(
            scan_type=ScanType.WIFI,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            # Parse the query to extract BSSID/SSID components
            parsed = self.parse_query(target)
            bssid, ssid = self.get_wifi_components(parsed)

            # Add parsed info to metadata
            result.metadata["bssid"] = bssid
            result.metadata["ssid"] = ssid

            # Add BSSID/SSID info to results
            if bssid:
                result.add_info("BSSID", bssid, source="Query Parser")
            if ssid:
                result.add_info("SSID", ssid, source="Query Parser")

            # Run plugins with the original target
            # Plugins will extract BSSID/SSID as needed
            plugin_results = await self._scan_with_plugins_async(
                target, "WIFI", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"WiFi scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    async def scan_domain_async(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Async domain scanning."""
        result = ScanResult(
            scan_type=ScanType.DOMAIN,
            target=target,
            status=ScanStatus.RUNNING,
        )
        start_time = time.time()

        try:
            progress_callback(0.05)

            plugin_results = await self._scan_with_plugins_async(
                target, "DOMAIN", progress_callback
            )
            for row in plugin_results:
                if "threat_level" in row and isinstance(row["threat_level"], str):
                    row["threat_level"] = ThreatLevel[row["threat_level"]]
                result.add_info(**row)

            progress_callback(1.0)
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            logger.error(f"Domain scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration = time.time() - start_time
        return result

    # === Generic Async Scan Method ===

    async def scan_async(
        self,
        target: str,
        scan_type: Optional[str] = None,
        progress_callback: Optional[Callable[[float], None]] = None,
    ) -> ScanResult:
        """Generic async scan method that auto-detects type if not provided.

        Args:
            target: The target to scan
            scan_type: Optional scan type override
            progress_callback: Optional progress callback

        Returns:
            ScanResult with findings
        """
        if progress_callback is None:
            progress_callback = lambda x: None

        # Auto-detect type if not provided
        if scan_type is None:
            scan_type = self.detect_input_type(target)

        if scan_type is None:
            result = ScanResult(
                scan_type=ScanType.EMAIL,  # Default
                target=target,
                status=ScanStatus.FAILED,
            )
            result.error_message = "Could not detect input type"
            return result

        # Route to appropriate async scan method
        scan_type_upper = scan_type.upper()

        if scan_type_upper == "IP":
            return await self.scan_ip_async(target, progress_callback)
        elif scan_type_upper == "EMAIL":
            return await self.scan_email_async(target, progress_callback)
        elif scan_type_upper == "PHONE":
            return await self.scan_phone_async(target, progress_callback)
        elif scan_type_upper == "USERNAME":
            return await self.scan_username_async(target, progress_callback)
        elif scan_type_upper == "ADDRESS":
            return await self.scan_address_async(target, progress_callback)
        elif scan_type_upper == "HASH":
            return await self.scan_hash_async(target, progress_callback)
        elif scan_type_upper == "WIFI":
            return await self.scan_wifi_async(target, progress_callback)
        elif scan_type_upper == "DOMAIN":
            return await self.scan_domain_async(target, progress_callback)
        else:
            result = ScanResult(
                scan_type=ScanType.EMAIL,
                target=target,
                status=ScanStatus.FAILED,
            )
            result.error_message = f"Unsupported scan type: {scan_type}"
            return result

    # === Backward Compatibility Methods ===

    def scan_ip(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for IP scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_ip_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_email(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for email scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_email_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_phone(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for phone scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_phone_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_username(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for username scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_username_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_address(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for address scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_address_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_hash(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for hash scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_hash_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_wifi(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for WiFi scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_wifi_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan_domain(
        self, target: str, progress_callback: Callable[[float], None]
    ) -> ScanResult:
        """Synchronous wrapper for domain scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_domain_async(target, progress_callback)
            )
        finally:
            loop.close()

    def scan(
        self,
        target: str,
        scan_type: Optional[str] = None,
        progress_callback: Optional[Callable[[float], None]] = None,
    ) -> ScanResult:
        """Synchronous wrapper for generic scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_async(target, scan_type, progress_callback)
            )
        finally:
            loop.close()

    async def scan_query_async(
        self,
        query: str,
        progress_callback: Optional[Callable[[float], None]] = None,
    ) -> ScanResult:
        """Execute a scan using the query parser system.

        This method supports:
        - Simple targets: user@example.com, 192.168.1.1, +1234567890
        - Structured queries: email:"user@example.com" ip:"8.8.8.8"
        - Combined queries: name:"John Doe" location:"New York"
        - WiFi queries: bssid:"AA:BB:CC:DD:EE:FF" ssid:"MyNetwork"

        Args:
            query: Raw query string
            progress_callback: Optional progress callback

        Returns:
            ScanResult with findings
        """
        if progress_callback is None:
            progress_callback = lambda x: None

        # Parse the query
        parsed = self.parse_query(query)

        if not parsed.is_valid:
            result = ScanResult(
                scan_type=ScanType.EMAIL,  # Default
                target=query,
                status=ScanStatus.FAILED,
            )
            result.error_message = "; ".join(parsed.errors)
            return result

        # Determine target and scan type from parsed query
        target = parsed.primary_target
        scan_type = parsed.scan_type

        if not scan_type:
            result = ScanResult(
                scan_type=ScanType.EMAIL,
                target=query,
                status=ScanStatus.FAILED,
            )
            result.error_message = "Could not determine query type"
            return result

        # For structured queries, pass the original query to allow plugins
        # to extract multiple fields if needed
        if parsed.query_type == "structured":
            # Pass the full query for structured queries
            return await self.scan_async(query, scan_type, progress_callback)
        else:
            # For simple queries, use the detected target
            return await self.scan_async(target, scan_type, progress_callback)

    def scan_query(
        self,
        query: str,
        progress_callback: Optional[Callable[[float], None]] = None,
    ) -> ScanResult:
        """Synchronous wrapper for query-based scanning."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self.scan_query_async(query, progress_callback)
            )
        finally:
            loop.close()

    async def get_available_plugins_async(self) -> List[Dict[str, Any]]:
        """Get list of available plugins with their metadata asynchronously."""
        await self._init_plugins()

        if not self._registry:
            return []

        plugins = []
        for name, plugin_class in self._registry.get_all().items():
            metadata = plugin_class.get_metadata()
            plugins.append(
                {
                    "name": metadata.name,
                    "display_name": metadata.display_name,
                    "description": metadata.description,
                    "category": metadata.category,
                    "scan_types": metadata.supported_scan_types,
                    "requires_api_key": len(metadata.api_key_requirements) > 0,
                    "is_enabled": self.config.is_service_enabled(metadata.name),
                }
            )

        return plugins

    def get_available_plugins(self) -> List[Dict[str, Any]]:
        """Synchronous wrapper for plugin listing."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.get_available_plugins_async())
        finally:
            loop.close()

    async def close(self):
        """Clean up resources."""
        # Close all plugin instances
        for plugin in self._plugin_instances.values():
            if hasattr(plugin, "close"):
                await plugin.close()

        # Close session
        if hasattr(self.session, "close"):
            await self.session.close()

    def __del__(self):
        """Cleanup on deletion."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.close())
        except RuntimeError:
            pass


class AsyncPluginWrapper:
    """Wrapper to make sync plugins work with async engine."""

    def __init__(self, plugin_class, config, session, semaphore):
        self.plugin_class = plugin_class
        self.config = config
        self.session = session
        self.semaphore = semaphore
        self._sync_plugin = None

    async def _get_sync_plugin(self):
        """Get sync plugin instance."""
        if self._sync_plugin is None:
            self._sync_plugin = self.plugin_class(self.config)
        return self._sync_plugin

    async def scan_async(
        self, target: str, scan_type: str, progress_callback: Callable[[float], None]
    ) -> List[Dict[str, Any]]:
        """Run sync plugin in thread pool."""
        plugin = await self._get_sync_plugin()

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, plugin.scan, target, scan_type, progress_callback
        )

    def scan(
        self, target: str, scan_type: str, progress_callback: Callable[[float], None]
    ) -> List[Dict[str, Any]]:
        """Synchronous scan method."""
        plugin = self.plugin_class(self.config)
        return plugin.scan(target, scan_type, progress_callback)

    @property
    def metadata(self):
        """Get plugin metadata."""
        return self.plugin_class.get_metadata()


# Global async engine instance
_async_engine_instance: Optional[AsyncOSINTEngine] = None


def get_async_engine(max_concurrent_requests: int = 100) -> AsyncOSINTEngine:
    """Get the global async OSINT engine instance."""
    global _async_engine_instance
    if _async_engine_instance is None:
        _async_engine_instance = AsyncOSINTEngine(max_concurrent_requests)
    return _async_engine_instance


def reset_async_engine(max_concurrent_requests: int = 100) -> AsyncOSINTEngine:
    """Reset the async engine instance (useful for testing)."""
    global _async_engine_instance
    _async_engine_instance = AsyncOSINTEngine(max_concurrent_requests)
    return _async_engine_instance
