"""WiFi Intelligence Plugins.

Plugins for SSID/BSSID geolocation and WiFi network intelligence.
"""

from .google_geolocation import GoogleGeolocationPlugin
from .wigle import WiGLEPlugin

__all__ = ["GoogleGeolocationPlugin", "WiGLEPlugin"]
