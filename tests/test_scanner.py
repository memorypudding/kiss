"""Tests for service scanner."""

import pytest
import responses
from unittest.mock import Mock, patch

from xsint.constants import ScanStatus
from xsint.models import ScanResult
from xsint.scanner.service_scanner import ServiceScanner


class TestServiceScanner:
    """Tests for ServiceScanner class."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock config."""
        config = Mock()
        config.get_api_key.return_value = "test_api_key"
        config.is_api_key_configured.return_value = True
        config.timeout = 5
        config.hibp_rate_limit = 0.1  # Fast for tests
        return config

    @pytest.fixture
    def scanner(self, mock_config):
        """Create a scanner with mocked config."""
        with patch("xsint.scanner.service_scanner.get_config", return_value=mock_config):
            return ServiceScanner()

    # =========================================================================
    # HIBP Breach Tests
    # =========================================================================

    @responses.activate
    def test_hibp_breach_found(self, scanner):
        """Test HIBP breach check when breaches are found."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/breachedaccount/test%40example.com?truncateResponse=false",
            json=[
                {"Name": "Breach1"},
                {"Name": "Breach2"},
            ],
            status=200,
        )

        result = scanner.check_hibp_breach("test@example.com")

        assert result.status == ScanStatus.FOUND
        assert "2 breaches" in result.details
        assert "Breach1" in result.details

    @responses.activate
    def test_hibp_breach_clean(self, scanner):
        """Test HIBP breach check when no breaches found."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/breachedaccount/clean%40example.com?truncateResponse=false",
            status=404,
        )

        result = scanner.check_hibp_breach("clean@example.com")

        assert result.status == ScanStatus.CLEAN
        assert "No breaches" in result.details

    @responses.activate
    def test_hibp_breach_unauthorized(self, scanner):
        """Test HIBP breach check with invalid API key."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/breachedaccount/test%40example.com?truncateResponse=false",
            status=401,
        )

        result = scanner.check_hibp_breach("test@example.com")

        assert result.status == ScanStatus.ERROR
        assert "Unauthorized" in result.details

    def test_hibp_breach_no_api_key(self, mock_config):
        """Test HIBP breach check without API key."""
        mock_config.is_api_key_configured.return_value = False

        with patch("xsint.scanner.service_scanner.get_config", return_value=mock_config):
            scanner = ServiceScanner()
            result = scanner.check_hibp_breach("test@example.com")

        assert result.status == ScanStatus.SKIPPED
        assert "API Key" in result.details

    @responses.activate
    def test_hibp_breach_phone_number(self, scanner):
        """Test HIBP breach check with phone number."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/breachedaccount/14155551234?truncateResponse=false",
            json=[{"Name": "PhoneBreach"}],
            status=200,
        )

        result = scanner.check_hibp_breach("+1-415-555-1234")

        assert result.status == ScanStatus.FOUND

    # =========================================================================
    # HIBP Paste Tests
    # =========================================================================

    @responses.activate
    def test_hibp_pastes_found(self, scanner):
        """Test HIBP paste check when pastes found."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/pasteaccount/test%40example.com",
            json=[
                {"Source": "Pastebin"},
                {"Source": "Ghostbin"},
            ],
            status=200,
        )

        result = scanner.check_hibp_pastes("test@example.com")

        assert result.status == ScanStatus.FOUND
        assert "2 pastes" in result.details

    @responses.activate
    def test_hibp_pastes_clean(self, scanner):
        """Test HIBP paste check when no pastes found."""
        responses.add(
            responses.GET,
            "https://haveibeenpwned.com/api/v3/pasteaccount/clean%40example.com",
            status=404,
        )

        result = scanner.check_hibp_pastes("clean@example.com")

        assert result.status == ScanStatus.CLEAN

    def test_hibp_pastes_not_email(self, scanner):
        """Test HIBP paste check with non-email returns None."""
        result = scanner.check_hibp_pastes("not-an-email")

        assert result is None

    # =========================================================================
    # Gravatar Tests
    # =========================================================================

    @responses.activate
    def test_gravatar_found(self, scanner):
        """Test Gravatar check when profile found."""
        responses.add(
            responses.GET,
            "https://en.gravatar.com/0bc83cb571cd1c50ba6f3e8a78ef1346.json",
            json={"entry": [{"preferredUsername": "testuser"}]},
            status=200,
        )

        result = scanner.check_gravatar("test@example.com")

        assert result is not None
        assert result.status == ScanStatus.FOUND
        assert "testuser" in result.details

    @responses.activate
    def test_gravatar_not_found(self, scanner):
        """Test Gravatar check when no profile."""
        responses.add(
            responses.GET,
            "https://en.gravatar.com/0bc83cb571cd1c50ba6f3e8a78ef1346.json",
            status=404,
        )

        result = scanner.check_gravatar("test@example.com")

        assert result is None

    # =========================================================================
    # IP Info Tests
    # =========================================================================

    @responses.activate
    def test_ip_info_success(self, scanner):
        """Test IP info lookup success."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/8.8.8.8/json",
            json={
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "org": "Google LLC",
            },
            status=200,
        )

        results = scanner.check_ip_info("8.8.8.8")

        assert len(results) >= 4
        cities = [r for r in results if r.service == "City"]
        assert len(cities) == 1
        assert cities[0].details == "Mountain View"

    @responses.activate
    def test_ip_info_timeout(self, scanner):
        """Test IP info lookup timeout."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/8.8.8.8/json",
            body=responses.ConnectionError("Connection refused"),
        )

        results = scanner.check_ip_info("8.8.8.8")

        assert len(results) == 1
        assert results[0].status == ScanStatus.ERROR

    # =========================================================================
    # Username Check Tests
    # =========================================================================

    @responses.activate
    def test_username_site_found(self, scanner):
        """Test username check when found on site."""
        responses.add(
            responses.GET,
            "https://github.com/testuser",
            status=200,
        )

        result = scanner.check_username_site(
            "testuser", "GitHub", "https://github.com/{username}"
        )

        assert result is not None
        assert result.status == ScanStatus.FOUND
        assert result.service == "GitHub"

    @responses.activate
    def test_username_site_not_found(self, scanner):
        """Test username check when not found on site."""
        responses.add(
            responses.GET,
            "https://github.com/nonexistentuser12345",
            status=404,
        )

        result = scanner.check_username_site(
            "nonexistentuser12345", "GitHub", "https://github.com/{username}"
        )

        assert result is None

    # =========================================================================
    # Batch Operations Tests
    # =========================================================================

    @responses.activate
    def test_run_email_checks(self, scanner):
        """Test running all email checks."""
        # Mock Gravatar
        responses.add(
            responses.GET,
            "https://en.gravatar.com/0bc83cb571cd1c50ba6f3e8a78ef1346.json",
            json={"entry": [{"preferredUsername": "testuser"}]},
            status=200,
        )

        # Mock Twitter
        responses.add(
            responses.GET,
            "https://api.twitter.com/i/users/email_available.json?email=test@example.com",
            json={"valid": False},
            status=200,
        )

        results = scanner.run_email_checks("test@example.com")

        # Should have found both
        assert len(results) == 2

    @responses.activate
    def test_run_username_checks(self, scanner):
        """Test running username checks across multiple sites."""
        responses.add(
            responses.GET,
            "https://github.com/testuser",
            status=200,
        )
        responses.add(
            responses.GET,
            "https://twitter.com/testuser",
            status=404,
        )

        sites = {
            "GitHub": "https://github.com/{username}",
            "Twitter": "https://twitter.com/{username}",
        }

        results = scanner.run_username_checks("testuser", sites)

        # Only GitHub should be found
        assert len(results) == 1
        assert results[0].service == "GitHub"
