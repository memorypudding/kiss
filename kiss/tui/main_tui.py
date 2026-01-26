"""Modern KISS TUI Implementation.

OpenCode-inspired design with centered search, live themes, and modular views.
Enhanced with dynamic API key management and improved navigation.
Supports structured queries with field:value syntax.
"""

import curses
import os
import threading
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config import get_config
from ..scanner.detectors import detect_input_type
from ..query_parser import parse_query, get_parser
from ..utils.logging import get_logger

logger = get_logger(__name__)


# View states
class View(Enum):
    SEARCH = "search"
    RESULTS = "results"
    SETTINGS = "settings"
    MODULES = "modules"
    HELP = "help"
    API_KEY_INPUT = "api_key_input"
    API_KEYS_MENU = "api_keys_menu"  # New dynamic API keys view


# Theme definitions with extended color support
THEMES = {
    "Ocean": {
        "primary": (curses.COLOR_CYAN, -1),
        "secondary": (curses.COLOR_BLUE, -1),
        "success": (curses.COLOR_GREEN, -1),
        "error": (curses.COLOR_RED, -1),
        "warning": (curses.COLOR_YELLOW, -1),
        "text": (curses.COLOR_WHITE, -1),
        "muted": (8, -1),
        "highlight": (curses.COLOR_CYAN, -1),
        "selected_fg": curses.COLOR_BLACK,
        "selected_bg": curses.COLOR_CYAN,
        "category": curses.COLOR_CYAN,
    },
    "Forest": {
        "primary": (curses.COLOR_GREEN, -1),
        "secondary": (curses.COLOR_YELLOW, -1),
        "success": (curses.COLOR_GREEN, -1),
        "error": (curses.COLOR_RED, -1),
        "warning": (curses.COLOR_YELLOW, -1),
        "text": (curses.COLOR_WHITE, -1),
        "muted": (8, -1),
        "highlight": (curses.COLOR_GREEN, -1),
        "selected_fg": curses.COLOR_BLACK,
        "selected_bg": curses.COLOR_GREEN,
        "category": curses.COLOR_GREEN,
    },
    "Sunset": {
        "primary": (curses.COLOR_RED, -1),
        "secondary": (curses.COLOR_YELLOW, -1),
        "success": (curses.COLOR_GREEN, -1),
        "error": (curses.COLOR_RED, -1),
        "warning": (curses.COLOR_YELLOW, -1),
        "text": (curses.COLOR_WHITE, -1),
        "muted": (8, -1),
        "highlight": (curses.COLOR_YELLOW, -1),
        "selected_fg": curses.COLOR_BLACK,
        "selected_bg": curses.COLOR_RED,
        "category": curses.COLOR_YELLOW,
    },
    "Midnight": {
        "primary": (curses.COLOR_MAGENTA, -1),
        "secondary": (curses.COLOR_BLUE, -1),
        "success": (curses.COLOR_GREEN, -1),
        "error": (curses.COLOR_RED, -1),
        "warning": (curses.COLOR_YELLOW, -1),
        "text": (curses.COLOR_WHITE, -1),
        "muted": (8, -1),
        "highlight": (curses.COLOR_MAGENTA, -1),
        "selected_fg": curses.COLOR_BLACK,
        "selected_bg": curses.COLOR_MAGENTA,
        "category": curses.COLOR_MAGENTA,
    },
}


class ModernTUI:
    """Modern KISS TUI with OpenCode-inspired design."""

    def __init__(self, stdscr):
        """Initialize modern TUI."""
        self.stdscr = stdscr
        self.running = True
        self.input_buffer = ""
        self.current_view = View.SEARCH
        self.previous_view = View.SEARCH

        # Scanning state
        self.is_scanning = False
        self.scan_progress = 0.0
        self.scan_results: List[Tuple[str, str]] = []
        self.current_target = ""
        self.current_scan_type = ""

        # Menu states
        self.settings_selection = 0
        self.modules_selection = 0
        self.results_scroll = 0
        self.help_scroll = 0

        # API key menu state
        self.api_keys_selection = 0
        self.api_keys_items: List[Tuple[str, Optional[str], Optional[str], bool, str, bool, bool]] = []

        # API key input state
        self.api_key_buffer = ""
        self.api_key_editing = ""

        # Mouse support
        self.mouse_enabled = False

        # Engine will be set externally
        self.engine = None

        # Config
        self.config = get_config()

        # Setup colors with current theme
        self._setup_colors()

        # Initialize mouse support
        self._init_mouse_support()

        # Expose callback interface
        self.log_callback = self._add_result

    def _init_mouse_support(self):
        """Initialize mouse support if available."""
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
            self.mouse_enabled = True
        except Exception:
            self.mouse_enabled = False

    def _setup_colors(self):
        """Setup color pairs based on current theme."""
        curses.start_color()
        curses.use_default_colors()

        theme_name = self.config.default_theme
        if theme_name not in THEMES:
            theme_name = "Ocean"

        theme = THEMES[theme_name]

        # Define standard color pairs (1-9)
        curses.init_pair(1, theme["primary"][0], theme["primary"][1])
        curses.init_pair(2, theme["success"][0], theme["success"][1])
        curses.init_pair(3, theme["error"][0], theme["error"][1])
        curses.init_pair(4, theme["warning"][0], theme["warning"][1])
        curses.init_pair(5, theme["text"][0], theme["text"][1])
        curses.init_pair(6, theme["secondary"][0], theme["secondary"][1])
        curses.init_pair(7, theme["muted"][0], theme["muted"][1])
        curses.init_pair(8, theme["highlight"][0], theme["highlight"][1])
        curses.init_pair(9, theme["selected_fg"], theme["selected_bg"])

        # Extended color pairs for settings UI (10-15)
        curses.init_pair(10, theme.get("category", curses.COLOR_CYAN), -1)  # Category headers
        curses.init_pair(11, curses.COLOR_GREEN, -1)  # Status OK
        curses.init_pair(12, curses.COLOR_RED, -1)  # Status missing (required)
        curses.init_pair(13, curses.COLOR_YELLOW, -1)  # Status optional
        curses.init_pair(14, curses.COLOR_CYAN, -1)  # Focused border
        curses.init_pair(15, 8, -1)  # Separator

        self.colors = {
            "primary": 1,
            "success": 2,
            "error": 3,
            "warning": 4,
            "text": 5,
            "secondary": 6,
            "muted": 7,
            "highlight": 8,
            "selected": 9,
            "category": 10,
            "status_ok": 11,
            "status_missing": 12,
            "status_optional": 13,
            "focused": 14,
            "separator": 15,
        }

    def _refresh_theme(self):
        """Refresh colors when theme changes."""
        self._setup_colors()

    def set_engine(self, engine):
        """Set the scan engine."""
        self.engine = engine

    def _add_result(self, message: str, color: str = "text"):
        """Add a result message."""
        self.scan_results.append((message, color))

    def _get_services_list(self) -> List[Tuple[str, str, bool]]:
        """Get list of services with their enabled status."""
        services = []

        # Try to get services from plugin system first
        try:
            from kiss.plugins.registry import get_registry

            registry = get_registry()
            registry.discover_plugins()

            for name, plugin_class in registry.get_all().items():
                metadata = plugin_class.get_metadata()
                enabled = self.config.is_service_enabled(name)
                services.append((name, metadata.display_name, enabled))

            return services
        except Exception:
            pass

        # Fallback to config services
        for name, svc in self.config.services.items():
            enabled = getattr(svc, "is_enabled", True)
            display_name = getattr(svc, "name", name.upper())
            services.append((name, display_name, enabled))
        return services

    def _toggle_service(self, service_name: str):
        """Toggle a service on/off."""
        if service_name in self.config.services:
            svc = self.config.services[service_name]
            svc.is_enabled = not getattr(svc, "is_enabled", True)
            self.config.save_to_file()

    def _get_api_keys_items(self) -> List[Tuple[str, Optional[str], Optional[str], bool, str, bool, bool]]:
        """Get API keys items with category headers for the menu.

        Returns:
            List of tuples: (display_text, key_name, category, is_configured,
                           masked_value, is_required, is_header)
        """
        try:
            from kiss.plugins.manager import APIKeyManager

            manager = APIKeyManager(self.config)
            return manager.get_flat_items_with_headers()
        except Exception as e:
            logger.debug(f"Failed to get API keys: {e}")
            # Fallback - just show HIBP key
            hibp_key = self.config.get_api_key("hibp") or os.environ.get(
                "KISS_HIBP_API_KEY", ""
            )
            is_configured = bool(hibp_key)
            masked = ("***" + hibp_key[-4:]) if hibp_key else "Not Set"

            return [
                ("Breach Detection", None, "Breach Detection", False, "", False, True),
                ("HIBP API Key", "hibp", "Breach Detection", is_configured, masked, True, False),
            ]

    def _get_unconfigured_api_keys_count(self) -> int:
        """Get count of unconfigured required API keys."""
        try:
            from kiss.plugins.manager import APIKeyManager

            manager = APIKeyManager(self.config)
            return manager.get_unconfigured_count()
        except Exception:
            return 0

    def run_scan(self, target: str, scan_type: str):
        """Execute a scan with progress tracking."""
        if not self.engine:
            self._add_result("No engine configured!", "error")
            return

        self.is_scanning = True
        self.scan_progress = 0.0
        self.scan_results = []
        self.current_target = target
        self.current_scan_type = scan_type

        def progress_update(val: float):
            self.scan_progress = val

        self._add_result(f"Target: {target}", "primary")
        self._add_result(f"Type: {scan_type}", "muted")
        self._add_result("", "text")

        try:
            result = None

            if scan_type == "IP":
                result = self.engine.scan_ip(target, progress_update)
            elif scan_type == "EMAIL":
                result = self.engine.scan_email(target, progress_update)
            elif scan_type == "PHONE":
                result = self.engine.scan_phone(target, progress_update)
            elif scan_type == "USERNAME":
                result = self.engine.scan_username(target, progress_update)
            elif scan_type == "ADDRESS":
                result = self.engine.scan_address(target, progress_update)
            elif scan_type == "HASH":
                result = self.engine.scan_hash(target, progress_update)
            elif scan_type == "WIFI":
                result = self.engine.scan_wifi(target, progress_update)
            elif scan_type == "DOMAIN":
                result = self.engine.scan_domain(target, progress_update)
            else:
                self._add_result(f"Unknown scan type: {scan_type}", "error")
                self.is_scanning = False
                return

            if result:
                self._add_result(f"Completed in {result.scan_duration:.2f}s", "success")
                self._add_result("", "text")

                if result.info_rows:
                    for row in result.info_rows:
                        color = "text"
                        marker = ""

                        if row.threat_level:
                            if row.threat_level.value in ["high", "critical"]:
                                marker = " [!]"
                                color = "error"
                            elif row.threat_level.value == "medium":
                                color = "warning"

                        label = row.label[:20].ljust(20)
                        self._add_result(f"{label} {row.value}{marker}", color)
                else:
                    self._add_result("No results found", "muted")

                if result.error_message:
                    self._add_result("", "text")
                    self._add_result(f"Error: {result.error_message}", "error")

        except Exception as e:
            self._add_result(f"Scan failed: {str(e)}", "error")
            logger.exception(f"Scan error for {target}")
        finally:
            self.is_scanning = False
            self.scan_progress = 1.0

    def _handle_search_input(self, key):
        """Handle input in search view."""
        if key == 27:  # Escape
            self.running = False
        elif key == 10:  # Enter
            if self.input_buffer.strip():
                query = self.input_buffer.strip()

                # Use query parser for structured queries
                parsed = parse_query(query)

                if parsed.is_valid and parsed.scan_type:
                    self.current_view = View.RESULTS
                    self.results_scroll = 0

                    # Pass the original query for structured queries
                    # Pass the primary target for simple queries
                    target = query if parsed.query_type == "structured" else parsed.primary_target
                    scan_type = parsed.scan_type

                    thread = threading.Thread(
                        target=self.run_scan, args=(target, scan_type), daemon=True
                    )
                    thread.start()
                else:
                    # Fallback to simple detection for backward compatibility
                    scan_type = detect_input_type(query)
                    if scan_type:
                        self.current_view = View.RESULTS
                        self.results_scroll = 0
                        thread = threading.Thread(
                            target=self.run_scan, args=(query, scan_type), daemon=True
                        )
                        thread.start()

                self.input_buffer = ""
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.input_buffer = self.input_buffer[:-1]
        elif key == curses.KEY_F1 or key == ord("?"):
            self.previous_view = self.current_view
            self.current_view = View.HELP
        elif key == curses.KEY_F2:
            self.previous_view = self.current_view
            self.current_view = View.SETTINGS
            self.settings_selection = 0
        elif key == curses.KEY_F3:
            self.previous_view = self.current_view
            self.current_view = View.MODULES
            self.modules_selection = 0
        elif 32 <= key <= 126:
            if len(self.input_buffer) < 100:
                self.input_buffer += chr(key)

    def _handle_results_input(self, key):
        """Handle input in results view."""
        if key == 27 or key == ord("q") or key == curses.KEY_BACKSPACE or key == 127:
            self.current_view = View.SEARCH
            self.scan_results = []
        elif key == curses.KEY_UP:
            self.results_scroll = max(0, self.results_scroll - 1)
        elif key == curses.KEY_DOWN:
            self.results_scroll = min(
                len(self.scan_results) - 1, self.results_scroll + 1
            )
        elif key == curses.KEY_PPAGE:
            self.results_scroll = max(0, self.results_scroll - 10)
        elif key == curses.KEY_NPAGE:
            self.results_scroll = min(
                len(self.scan_results) - 1, self.results_scroll + 10
            )
        elif key == curses.KEY_HOME:
            self.results_scroll = 0
        elif key == curses.KEY_END:
            self.results_scroll = max(0, len(self.scan_results) - 1)

    def _handle_settings_input(self, key):
        """Handle input in settings view."""
        settings_items = self._get_settings_items()
        max_idx = len(settings_items) - 1

        if key == 27 or key == ord("q"):
            self.current_view = self.previous_view
        elif key == curses.KEY_UP:
            self.settings_selection = max(0, self.settings_selection - 1)
            while (
                self.settings_selection > 0
                and settings_items[self.settings_selection][2] == "separator"
            ):
                self.settings_selection -= 1
        elif key == curses.KEY_DOWN:
            self.settings_selection = min(max_idx, self.settings_selection + 1)
            while (
                self.settings_selection < max_idx
                and settings_items[self.settings_selection][2] == "separator"
            ):
                self.settings_selection += 1
        elif key == 10:  # Enter
            self._handle_settings_action(settings_items[self.settings_selection])
        elif key == 9:  # Tab - jump to next section
            # Find next non-separator after current
            for i in range(self.settings_selection + 1, len(settings_items)):
                if settings_items[i][2] != "separator":
                    self.settings_selection = i
                    break

    def _get_settings_items(self) -> List[Tuple[str, str, str]]:
        """Get settings menu items."""
        unconfigured = self._get_unconfigured_api_keys_count()
        api_keys_status = f"{unconfigured} missing" if unconfigured else "All Set"

        return [
            ("API Keys", api_keys_status, "api_keys"),
            ("", "", "separator"),
            ("Theme", self.config.default_theme, "theme"),
            ("Request Timeout", f"{self.config.request_timeout}s", "timeout"),
            ("Max Retries", str(self.config.max_retries), "retries"),
            ("", "", "separator"),
            ("Manage Modules", "->", "modules"),
            ("", "", "separator"),
            ("Back", "", "back"),
        ]

    def _handle_settings_action(self, item):
        """Handle settings item selection."""
        key = item[2]

        if key == "back":
            self.current_view = self.previous_view
        elif key == "api_keys":
            self.api_keys_selection = 0
            self.api_keys_items = self._get_api_keys_items()
            self.current_view = View.API_KEYS_MENU
        elif key == "theme":
            themes = list(THEMES.keys())
            current_idx = (
                themes.index(self.config.default_theme)
                if self.config.default_theme in themes
                else 0
            )
            self.config.default_theme = themes[(current_idx + 1) % len(themes)]
            self.config.save_to_file()
            self._refresh_theme()
        elif key == "timeout":
            timeouts = [10, 15, 30, 60]
            current_idx = (
                timeouts.index(self.config.request_timeout)
                if self.config.request_timeout in timeouts
                else 2
            )
            self.config.request_timeout = timeouts[(current_idx + 1) % len(timeouts)]
            self.config.save_to_file()
        elif key == "retries":
            self.config.max_retries = (self.config.max_retries % 5) + 1
            self.config.save_to_file()
        elif key == "modules":
            self.current_view = View.MODULES
            self.modules_selection = 0

    def _handle_modules_input(self, key):
        """Handle input in modules view."""
        services = self._get_services_list()
        max_idx = len(services)  # +1 for back button

        if key == 27 or key == ord("q"):
            self.current_view = View.SETTINGS
        elif key == curses.KEY_UP:
            self.modules_selection = max(0, self.modules_selection - 1)
        elif key == curses.KEY_DOWN:
            self.modules_selection = min(max_idx, self.modules_selection + 1)
        elif key == 10 or key == ord(" "):  # Enter or Space
            if self.modules_selection < len(services):
                service_name = services[self.modules_selection][0]
                self._toggle_service(service_name)
            else:
                self.current_view = View.SETTINGS
        elif key == curses.KEY_HOME:
            self.modules_selection = 0
        elif key == curses.KEY_END:
            self.modules_selection = max_idx

    def _handle_api_keys_menu_input(self, key):
        """Handle input in API keys menu view."""
        items = self.api_keys_items
        # Count non-header items for navigation
        selectable_items = [(i, item) for i, item in enumerate(items) if not item[6]]
        max_selectable = len(selectable_items)

        if key == 27 or key == ord("q"):
            self.current_view = View.SETTINGS
        elif key == curses.KEY_UP:
            # Find previous selectable item
            current_pos = self.api_keys_selection
            for i in range(current_pos - 1, -1, -1):
                if not items[i][6]:  # Not a header
                    self.api_keys_selection = i
                    break
        elif key == curses.KEY_DOWN:
            # Find next selectable item
            current_pos = self.api_keys_selection
            for i in range(current_pos + 1, len(items)):
                if not items[i][6]:  # Not a header
                    self.api_keys_selection = i
                    break
        elif key == 10:  # Enter - edit selected key
            if self.api_keys_selection < len(items):
                item = items[self.api_keys_selection]
                if not item[6] and item[1]:  # Not a header and has key_name
                    self.api_key_editing = item[1]
                    self.api_key_buffer = ""
                    self.current_view = View.API_KEY_INPUT
        elif key == curses.KEY_HOME:
            # Go to first selectable item
            for i, item in enumerate(items):
                if not item[6]:
                    self.api_keys_selection = i
                    break
        elif key == curses.KEY_END:
            # Go to last selectable item
            for i in range(len(items) - 1, -1, -1):
                if not items[i][6]:
                    self.api_keys_selection = i
                    break
        elif key == curses.KEY_PPAGE:
            # Page up - move up 5 selectable items
            count = 0
            for i in range(self.api_keys_selection - 1, -1, -1):
                if not items[i][6]:
                    self.api_keys_selection = i
                    count += 1
                    if count >= 5:
                        break
        elif key == curses.KEY_NPAGE:
            # Page down - move down 5 selectable items
            count = 0
            for i in range(self.api_keys_selection + 1, len(items)):
                if not items[i][6]:
                    self.api_keys_selection = i
                    count += 1
                    if count >= 5:
                        break

    def _handle_help_input(self, key):
        """Handle input in help view."""
        if key == 27 or key == ord("q") or key == curses.KEY_BACKSPACE or key == 127:
            self.current_view = self.previous_view
        elif key == curses.KEY_UP:
            self.help_scroll = max(0, self.help_scroll - 1)
        elif key == curses.KEY_DOWN:
            self.help_scroll += 1
        elif key == curses.KEY_PPAGE:
            self.help_scroll = max(0, self.help_scroll - 10)
        elif key == curses.KEY_NPAGE:
            self.help_scroll += 10
        elif key == curses.KEY_HOME:
            self.help_scroll = 0

    def _handle_api_key_input(self, key):
        """Handle API key input."""
        if key == 27:  # Escape - cancel
            self.current_view = View.API_KEYS_MENU
            self.api_key_buffer = ""
        elif key == 10:  # Enter - save
            if self.api_key_buffer:
                # Save to config
                from ..models import APIKey

                api_key = APIKey(
                    name=f"{self.api_key_editing}_api_key",
                    key=self.api_key_buffer,
                    service=self.api_key_editing,
                )
                self.config.api_keys[self.api_key_editing] = api_key
                self.config.save_to_file()
                # Also set environment variable for current session
                os.environ[f"KISS_{self.api_key_editing.upper()}_API_KEY"] = (
                    self.api_key_buffer
                )
            # Refresh the items list
            self.api_keys_items = self._get_api_keys_items()
            self.current_view = View.API_KEYS_MENU
            self.api_key_buffer = ""
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.api_key_buffer = self.api_key_buffer[:-1]
        elif 32 <= key <= 126:
            self.api_key_buffer += chr(key)

    def _handle_mouse_click(self, mx: int, my: int, button: int):
        """Handle mouse click events."""
        # This is a placeholder for mouse click handling
        # Could be extended to handle clicks on menu items
        pass

    def handle_input(self, key):
        """Route input to current view handler."""
        # Handle mouse events
        if key == curses.KEY_MOUSE and self.mouse_enabled:
            try:
                _, mx, my, _, button = curses.getmouse()
                self._handle_mouse_click(mx, my, button)
                return
            except Exception:
                pass

        if self.current_view == View.SEARCH:
            self._handle_search_input(key)
        elif self.current_view == View.RESULTS:
            self._handle_results_input(key)
        elif self.current_view == View.SETTINGS:
            self._handle_settings_input(key)
        elif self.current_view == View.MODULES:
            self._handle_modules_input(key)
        elif self.current_view == View.HELP:
            self._handle_help_input(key)
        elif self.current_view == View.API_KEY_INPUT:
            self._handle_api_key_input(key)
        elif self.current_view == View.API_KEYS_MENU:
            self._handle_api_keys_menu_input(key)

    def _draw_box(self, y, x, h, w, title="", title_color="primary"):
        """Draw a box with rounded-style corners."""
        if h < 2 or w < 2:
            return

        color = curses.color_pair(self.colors["muted"])
        title_clr = curses.color_pair(self.colors[title_color])

        try:
            # Top border
            self.stdscr.addstr(y, x, "╭" + "─" * (w - 2) + "╮", color)
            # Sides
            for i in range(1, h - 1):
                self.stdscr.addstr(y + i, x, "│", color)
                self.stdscr.addstr(y + i, x + w - 1, "│", color)
            # Bottom border
            self.stdscr.addstr(y + h - 1, x, "╰" + "─" * (w - 2) + "╯", color)

            # Title
            if title:
                title_str = f" {title} "
                title_x = x + (w - len(title_str)) // 2
                self.stdscr.addstr(y, title_x, title_str, title_clr | curses.A_BOLD)
        except curses.error:
            pass

    def _render_search_view(self):
        """Render the search view with centered search box."""
        h, w = self.stdscr.getmaxyx()

        # Logo - centered at top
        logo_lines = [
            " █        ▀                 ",
            " █   ▄  ▄▄▄     ▄▄▄    ▄▄▄  ",
            " █ ▄▀     █    █   ▀  █   ▀ ",
            " █▀█      █     ▀▀▀▄   ▀▀▀▄ ",
            " █  ▀▄  ▄▄█▄▄  ▀▄▄▄▀  ▀▄▄▄▀ ",
            "              A modern OSINT toolkit              ",
        ]

        logo_y = max(2, (h - 15) // 3)
        for i, line in enumerate(logo_lines):
            x = max(0, (w - len(line)) // 2)
            try:
                self.stdscr.addstr(
                    logo_y + i,
                    x,
                    line,
                    curses.color_pair(self.colors["primary"]) | curses.A_BOLD,
                )
            except curses.error:
                pass

        # Search box - centered
        box_w = min(60, w - 4)
        box_h = 3
        box_x = (w - box_w) // 2
        box_y = logo_y + len(logo_lines) + 3

        self._draw_box(box_y, box_x, box_h, box_w, "Search")

        # Input text
        prompt = "> "
        cursor = "█" if int(time.time() * 2) % 2 == 0 else " "
        display_text = prompt + self.input_buffer + cursor
        max_len = box_w - 4
        if len(display_text) > max_len:
            display_text = prompt + "..." + self.input_buffer[-(max_len - 6) :] + cursor

        try:
            self.stdscr.addstr(
                box_y + 1,
                box_x + 2,
                display_text[:max_len],
                curses.color_pair(self.colors["text"]),
            )
        except curses.error:
            pass

        # Hint text below search
        hints = [
            "IP, email, phone, @username, address, BSSID, or domain",
            'Structured: email:"test@example.com" bssid:"AA:BB:CC:DD:EE:FF"',
        ]
        for i, hint in enumerate(hints):
            hint_x = (w - len(hint)) // 2
            try:
                self.stdscr.addstr(
                    box_y + box_h + 1 + i,
                    hint_x,
                    hint,
                    curses.color_pair(self.colors["muted"]),
                )
            except curses.error:
                pass

        # Bottom bar with options
        bar_y = h - 2
        options = "  F1 Help  │  F2 Settings  │  F3 Modules  │  ESC Exit  "
        bar_x = (w - len(options)) // 2
        try:
            self.stdscr.addstr(
                bar_y, bar_x, options, curses.color_pair(self.colors["muted"])
            )
        except curses.error:
            pass

    def _render_results_view(self):
        """Render the results view."""
        h, w = self.stdscr.getmaxyx()

        # Results box - takes most of screen
        box_w = min(80, w - 4)
        box_h = h - 6
        box_x = (w - box_w) // 2
        box_y = 2

        title = f"Results: {self.current_target}"
        if self.is_scanning:
            pct = int(self.scan_progress * 100)
            title = f"Scanning... {pct}%"

        self._draw_box(
            box_y,
            box_x,
            box_h,
            box_w,
            title,
            "warning" if self.is_scanning else "success",
        )

        # Results content
        visible_h = box_h - 2
        start_idx = self.results_scroll

        for i in range(visible_h):
            idx = start_idx + i
            if idx >= len(self.scan_results):
                break

            msg, color = self.scan_results[idx]
            try:
                display_msg = msg[: box_w - 4]
                self.stdscr.addstr(
                    box_y + 1 + i,
                    box_x + 2,
                    display_msg,
                    curses.color_pair(self.colors.get(color, self.colors["text"])),
                )
            except curses.error:
                pass

        # Scroll indicator
        if len(self.scan_results) > visible_h:
            try:
                indicator = f" {self.results_scroll + 1}/{len(self.scan_results)} "
                self.stdscr.addstr(
                    box_y,
                    box_x + box_w - len(indicator) - 2,
                    indicator,
                    curses.color_pair(self.colors["muted"]),
                )
            except curses.error:
                pass

        # Bottom bar
        bar_y = h - 2
        if self.is_scanning:
            options = "  Scanning...  "
        else:
            options = "  ↑↓ Scroll  │  PgUp/PgDn  │  Q/ESC Back  "
        bar_x = (w - len(options)) // 2
        try:
            self.stdscr.addstr(
                bar_y, bar_x, options, curses.color_pair(self.colors["muted"])
            )
        except curses.error:
            pass

    def _render_settings_view(self):
        """Render the settings view."""
        h, w = self.stdscr.getmaxyx()

        box_w = 50
        box_h = 15
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2

        self._draw_box(box_y, box_x, box_h, box_w, "Settings")

        settings = self._get_settings_items()

        row = 0
        for i, (label, value, key) in enumerate(settings):
            if key == "separator":
                row += 1
                continue

            y = box_y + 2 + row
            x = box_x + 2

            # Selection highlight
            if i == self.settings_selection:
                attr = curses.color_pair(self.colors["selected"]) | curses.A_BOLD
                try:
                    self.stdscr.addstr(y, x, " " * (box_w - 4), attr)
                except curses.error:
                    pass
            else:
                attr = curses.color_pair(self.colors["text"])

            try:
                if key == "back":
                    self.stdscr.addstr(y, x + 2, "← " + label, attr)
                elif key == "api_keys":
                    # Special coloring for API keys based on status
                    self.stdscr.addstr(y, x + 2, label, attr)
                    unconfigured = self._get_unconfigured_api_keys_count()
                    if unconfigured > 0:
                        val_attr = curses.color_pair(self.colors["status_missing"])
                    else:
                        val_attr = curses.color_pair(self.colors["status_ok"])
                    val_x = box_x + box_w - len(value) - 4
                    if i == self.settings_selection:
                        val_attr = attr
                    self.stdscr.addstr(y, val_x, value, val_attr)
                else:
                    self.stdscr.addstr(y, x + 2, label, attr)
                    if value:
                        val_x = box_x + box_w - len(value) - 4
                        self.stdscr.addstr(y, val_x, value, attr)
            except curses.error:
                pass

            row += 1

        # Instructions
        try:
            self.stdscr.addstr(
                box_y + box_h - 2,
                box_x + 2,
                "↑↓ Navigate  Enter Select  ESC Close",
                curses.color_pair(self.colors["muted"]),
            )
        except curses.error:
            pass

    def _render_api_keys_menu(self):
        """Render the dynamic API keys settings menu."""
        h, w = self.stdscr.getmaxyx()

        items = self.api_keys_items
        if not items:
            items = self._get_api_keys_items()
            self.api_keys_items = items

        # Calculate box dimensions
        box_w = min(65, w - 4)
        total_rows = len(items) + 4  # Items + padding + back button
        box_h = min(total_rows + 4, h - 4)
        box_x = (w - box_w) // 2
        box_y = max(2, (h - box_h) // 2)

        # Count unconfigured required keys
        unconfigured = sum(1 for item in items if not item[6] and item[5] and not item[3])
        title = f"API Keys ({unconfigured} missing)" if unconfigured else "API Keys"
        title_color = "warning" if unconfigured else "success"

        self._draw_box(box_y, box_x, box_h, box_w, title, title_color)

        # Render items
        visible_h = box_h - 4
        row = 0

        for i, item in enumerate(items):
            if row >= visible_h:
                break

            display_text, key_name, category, is_configured, masked_value, is_required, is_header = item
            y = box_y + 2 + row

            if is_header:
                # Category header - distinctive styling
                try:
                    header_attr = curses.color_pair(self.colors["category"]) | curses.A_BOLD
                    header_text = f"═══ {display_text} ═══"
                    header_x = box_x + (box_w - len(header_text)) // 2
                    self.stdscr.addstr(y, header_x, header_text, header_attr)
                except curses.error:
                    pass
            else:
                # Regular item
                is_selected = i == self.api_keys_selection
                x = box_x + 2

                # Selection highlight
                if is_selected:
                    attr = curses.color_pair(self.colors["selected"]) | curses.A_BOLD
                    try:
                        self.stdscr.addstr(y, x, " " * (box_w - 4), attr)
                    except curses.error:
                        pass
                else:
                    attr = curses.color_pair(self.colors["text"])

                # Status indicator
                if is_configured:
                    indicator = "[OK]"
                    ind_color = self.colors["status_ok"]
                elif is_required:
                    indicator = "[!!]"
                    ind_color = self.colors["status_missing"]
                else:
                    indicator = "[--]"
                    ind_color = self.colors["status_optional"]

                try:
                    # Indicator (always colored unless selected)
                    ind_attr = attr if is_selected else curses.color_pair(ind_color)
                    self.stdscr.addstr(y, x + 2, indicator, ind_attr)

                    # Name
                    name_text = display_text[:28].ljust(28)
                    self.stdscr.addstr(y, x + 7, name_text, attr)

                    # Value (masked)
                    val_text = masked_value[:15] if masked_value else "Not Set"
                    val_x = box_x + box_w - len(val_text) - 4
                    self.stdscr.addstr(y, val_x, val_text, attr)
                except curses.error:
                    pass

            row += 1

        # Back button
        back_y = box_y + box_h - 3
        back_x = box_x + 2
        # Check if back is selected (selection beyond items means back)
        selectable_count = sum(1 for item in items if not item[6])
        is_back_selected = self.api_keys_selection >= len(items) - 1

        try:
            if is_back_selected:
                attr = curses.color_pair(self.colors["selected"]) | curses.A_BOLD
                self.stdscr.addstr(back_y, back_x, " " * (box_w - 4), attr)
            else:
                attr = curses.color_pair(self.colors["text"])
            self.stdscr.addstr(back_y, back_x + 2, "← Back to Settings", attr)
        except curses.error:
            pass

        # Instructions
        try:
            self.stdscr.addstr(
                box_y + box_h - 2,
                box_x + 2,
                "↑↓ Navigate  Enter Edit  ESC Back",
                curses.color_pair(self.colors["muted"]),
            )
        except curses.error:
            pass

    def _render_modules_view(self):
        """Render the modules/services view."""
        h, w = self.stdscr.getmaxyx()

        services = self._get_services_list()

        box_w = 50
        box_h = min(len(services) + 6, h - 4)
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2

        self._draw_box(box_y, box_x, box_h, box_w, "Modules")

        for i, (name, display_name, enabled) in enumerate(services):
            y = box_y + 2 + i
            x = box_x + 2

            if i == self.modules_selection:
                attr = curses.color_pair(self.colors["selected"]) | curses.A_BOLD
                try:
                    self.stdscr.addstr(y, x, " " * (box_w - 4), attr)
                except curses.error:
                    pass
            else:
                attr = curses.color_pair(self.colors["text"])

            checkbox = "[✓]" if enabled else "[ ]"
            status_color = self.colors["success"] if enabled else self.colors["muted"]

            try:
                if i == self.modules_selection:
                    self.stdscr.addstr(y, x + 2, checkbox, attr)
                    self.stdscr.addstr(y, x + 6, display_name, attr)
                else:
                    self.stdscr.addstr(
                        y, x + 2, checkbox, curses.color_pair(status_color)
                    )
                    self.stdscr.addstr(y, x + 6, display_name, attr)
            except curses.error:
                pass

        # Back button
        back_y = box_y + 2 + len(services)
        back_x = box_x + 2
        if self.modules_selection == len(services):
            attr = curses.color_pair(self.colors["selected"]) | curses.A_BOLD
            try:
                self.stdscr.addstr(back_y, back_x, " " * (box_w - 4), attr)
            except curses.error:
                pass
        else:
            attr = curses.color_pair(self.colors["text"])

        try:
            self.stdscr.addstr(back_y, back_x + 2, "← Back", attr)
        except curses.error:
            pass

        # Instructions
        try:
            self.stdscr.addstr(
                box_y + box_h - 2,
                box_x + 2,
                "↑↓ Navigate  Space Toggle  ESC Back",
                curses.color_pair(self.colors["muted"]),
            )
        except curses.error:
            pass

    def _render_help_view(self):
        """Render the help view."""
        h, w = self.stdscr.getmaxyx()

        help_content = [
            ("KISS - Modern OSINT Toolkit", "primary"),
            ("", "text"),
            ("SUPPORTED TARGETS", "highlight"),
            ("  IP Address      8.8.8.8, 192.168.1.1", "text"),
            ("  Email           user@example.com", "text"),
            ("  Phone           +1-555-123-4567", "text"),
            ("  Username        @johndoe", "text"),
            ("  Address         123 Main St, City", "text"),
            ("  Hash            MD5, SHA1, SHA256...", "text"),
            ("  BSSID/WiFi      AA:BB:CC:DD:EE:FF", "text"),
            ("  Domain          example.com", "text"),
            ("", "text"),
            ("STRUCTURED QUERIES", "highlight"),
            ('  email:"user@example.com"', "text"),
            ('  bssid:"AA:BB:CC:DD:EE:FF" ssid:"MyNetwork"', "text"),
            ('  ip:"8.8.8.8" phone:"+1234567890"', "text"),
            ("", "text"),
            ("KEYBOARD SHORTCUTS", "highlight"),
            ("  F1              Show this help", "text"),
            ("  F2              Open settings", "text"),
            ("  F3              Manage modules", "text"),
            ("  ESC             Exit / Go back", "text"),
            ("  Enter           Search / Select", "text"),
            ("  ↑↓              Navigate / Scroll", "text"),
            ("  PgUp/PgDn       Scroll by page", "text"),
            ("  Home/End        Jump to start/end", "text"),
            ("  Tab             Next section", "text"),
            ("  Space           Toggle selection", "text"),
            ("", "text"),
            ("PLUGIN SYSTEM", "highlight"),
            ("  Custom plugins: ~/.xsint/plugins/", "text"),
            ("  Plugins are auto-discovered on startup", "text"),
            ("", "text"),
            ("Press ESC or Q to close", "muted"),
        ]

        box_w = min(60, w - 4)
        box_h = min(len(help_content) + 4, h - 4)
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2

        self._draw_box(box_y, box_x, box_h, box_w, "Help")

        visible_h = box_h - 2
        start_idx = self.help_scroll

        for i in range(visible_h):
            idx = start_idx + i
            if idx >= len(help_content):
                break

            text, color = help_content[idx]
            try:
                self.stdscr.addstr(
                    box_y + 1 + i,
                    box_x + 2,
                    text[: box_w - 4],
                    curses.color_pair(self.colors.get(color, self.colors["text"])),
                )
            except curses.error:
                pass

    def _render_api_key_input(self):
        """Render API key input dialog."""
        h, w = self.stdscr.getmaxyx()

        box_w = 50
        box_h = 7
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2

        self._draw_box(
            box_y, box_x, box_h, box_w, f"Enter {self.api_key_editing.upper()} API Key"
        )

        # Input field
        input_y = box_y + 2
        input_x = box_x + 2

        # Show masked input
        if self.api_key_buffer:
            if len(self.api_key_buffer) > 4:
                masked = "*" * (len(self.api_key_buffer) - 4) + self.api_key_buffer[-4:]
            else:
                masked = "*" * len(self.api_key_buffer)
        else:
            masked = ""

        cursor = "█" if int(time.time() * 2) % 2 == 0 else " "
        display = masked + cursor

        try:
            self.stdscr.addstr(
                input_y,
                input_x,
                "> " + display[: box_w - 6],
                curses.color_pair(self.colors["text"]),
            )
        except curses.error:
            pass

        # Instructions
        try:
            self.stdscr.addstr(
                box_y + box_h - 2,
                box_x + 2,
                "Enter to save  ESC to cancel",
                curses.color_pair(self.colors["muted"]),
            )
        except curses.error:
            pass

    def _render(self):
        """Render current view."""
        self.stdscr.erase()

        if self.current_view == View.SEARCH:
            self._render_search_view()
        elif self.current_view == View.RESULTS:
            self._render_results_view()
        elif self.current_view == View.SETTINGS:
            self._render_settings_view()
        elif self.current_view == View.MODULES:
            self._render_modules_view()
        elif self.current_view == View.HELP:
            self._render_help_view()
        elif self.current_view == View.API_KEY_INPUT:
            self._render_api_key_input()
        elif self.current_view == View.API_KEYS_MENU:
            self._render_api_keys_menu()

        self.stdscr.refresh()

    def loop(self):
        """Main TUI event loop."""
        curses.curs_set(0)
        self.stdscr.nodelay(1)
        curses.noecho()

        try:
            while self.running:
                self._render()

                key = self.stdscr.getch()
                if key != -1:
                    self.handle_input(key)

                time.sleep(0.03)

        except KeyboardInterrupt:
            self.running = False
        finally:
            curses.curs_set(1)
            self.stdscr.nodelay(0)
            curses.echo()
