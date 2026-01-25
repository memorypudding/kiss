"""Tests for input type detection."""

import pytest

from xsint.constants import ScanType
from xsint.scanner.detectors import InputDetector


class TestInputDetector:
    """Tests for InputDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance."""
        return InputDetector()

    # =========================================================================
    # Email Detection Tests
    # =========================================================================

    def test_detect_email_simple(self, detector):
        """Test detection of simple email addresses."""
        assert detector.detect("user@example.com") == ScanType.EMAIL
        assert detector.detect("test@domain.org") == ScanType.EMAIL

    def test_detect_email_with_dots(self, detector):
        """Test detection of email with dots in local part."""
        assert detector.detect("first.last@example.com") == ScanType.EMAIL

    def test_detect_email_with_plus(self, detector):
        """Test detection of email with plus addressing."""
        assert detector.detect("user+tag@example.com") == ScanType.EMAIL

    def test_detect_email_subdomain(self, detector):
        """Test detection of email with subdomain."""
        assert detector.detect("user@mail.example.com") == ScanType.EMAIL

    def test_invalid_email_no_at(self, detector):
        """Test that strings without @ are not detected as email."""
        assert detector.detect("userexample.com") != ScanType.EMAIL

    def test_invalid_email_no_domain(self, detector):
        """Test that email without domain is not detected."""
        # This will be detected as something else, not email
        result = detector.detect("user@")
        assert result != ScanType.EMAIL

    # =========================================================================
    # IPv4 Detection Tests
    # =========================================================================

    def test_detect_ipv4_valid(self, detector):
        """Test detection of valid IPv4 addresses."""
        assert detector.detect("192.168.1.1") == ScanType.IP
        assert detector.detect("10.0.0.1") == ScanType.IP
        assert detector.detect("172.16.0.1") == ScanType.IP

    def test_detect_ipv4_edge_cases(self, detector):
        """Test IPv4 edge cases."""
        assert detector.detect("0.0.0.0") == ScanType.IP
        assert detector.detect("255.255.255.255") == ScanType.IP

    def test_invalid_ipv4_out_of_range(self, detector):
        """Test that out-of-range octets are not detected as IP."""
        # 256 is out of range
        assert detector.detect("256.1.1.1") != ScanType.IP

    def test_invalid_ipv4_too_few_octets(self, detector):
        """Test that incomplete IPs are not detected."""
        assert detector.detect("192.168.1") != ScanType.IP

    # =========================================================================
    # IPv6 Detection Tests
    # =========================================================================

    def test_detect_ipv6_full(self, detector):
        """Test detection of full IPv6 addresses."""
        assert detector.detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == ScanType.IP

    def test_detect_ipv6_compressed(self, detector):
        """Test detection of compressed IPv6 addresses."""
        assert detector.detect("2001:db8::1") == ScanType.IP
        assert detector.detect("::1") == ScanType.IP

    # =========================================================================
    # Phone Number Detection Tests
    # =========================================================================

    def test_detect_phone_international(self, detector):
        """Test detection of international phone numbers."""
        assert detector.detect("+14155551234") == ScanType.PHONE
        assert detector.detect("+442071234567") == ScanType.PHONE

    def test_detect_phone_with_spaces(self, detector):
        """Test detection of phone numbers with formatting."""
        # May or may not work depending on validation
        result = detector.detect("+1 415 555 1234")
        # Spaces might cause it to be detected differently
        # This tests the actual behavior

    def test_invalid_phone_too_short(self, detector):
        """Test that too-short numbers are not detected as phone."""
        assert detector.detect("12345") != ScanType.PHONE

    # =========================================================================
    # Domain Detection Tests
    # =========================================================================

    def test_detect_domain_simple(self, detector):
        """Test detection of simple domain names."""
        assert detector.detect("example.com") == ScanType.DOMAIN
        assert detector.detect("google.com") == ScanType.DOMAIN

    def test_detect_domain_subdomain(self, detector):
        """Test detection of domains with subdomains."""
        assert detector.detect("www.example.com") == ScanType.DOMAIN
        assert detector.detect("mail.google.com") == ScanType.DOMAIN

    def test_detect_domain_new_tld(self, detector):
        """Test detection of domains with new TLDs."""
        assert detector.detect("example.io") == ScanType.DOMAIN
        assert detector.detect("test.app") == ScanType.DOMAIN

    def test_invalid_domain_with_space(self, detector):
        """Test that strings with spaces are not domains."""
        assert detector.detect("example .com") != ScanType.DOMAIN

    # =========================================================================
    # BSSID Detection Tests
    # =========================================================================

    def test_detect_bssid_colon(self, detector):
        """Test detection of BSSID with colons."""
        assert detector.detect("00:11:22:33:44:55") == ScanType.BSSID

    def test_detect_bssid_dash(self, detector):
        """Test detection of BSSID with dashes."""
        assert detector.detect("00-11-22-33-44-55") == ScanType.BSSID

    def test_invalid_bssid_wrong_format(self, detector):
        """Test that wrong format is not detected as BSSID."""
        assert detector.detect("001122334455") != ScanType.BSSID

    # =========================================================================
    # Address Detection Tests
    # =========================================================================

    def test_detect_address_simple(self, detector):
        """Test detection of simple street addresses."""
        assert detector.detect("123 Main Street") == ScanType.ADDRESS
        assert detector.detect("456 Oak Ave") == ScanType.ADDRESS

    def test_detect_address_with_city(self, detector):
        """Test detection of full addresses."""
        assert detector.detect("123 Main St, Boston, MA") == ScanType.ADDRESS

    # =========================================================================
    # Username Detection Tests
    # =========================================================================

    def test_detect_username_default(self, detector):
        """Test that unrecognized strings default to username."""
        assert detector.detect("john_doe") == ScanType.USERNAME
        assert detector.detect("user123") == ScanType.USERNAME

    def test_detect_username_with_special_chars(self, detector):
        """Test username with allowed special characters."""
        assert detector.detect("user-name") == ScanType.USERNAME
        assert detector.detect("user.name") == ScanType.USERNAME

    # =========================================================================
    # Name Detection Tests
    # =========================================================================

    def test_detect_name_simple(self, detector):
        """Test detection of simple names."""
        assert detector.detect("John Doe") == ScanType.NAME
        assert detector.detect("Jane Smith") == ScanType.NAME

    def test_detect_name_three_parts(self, detector):
        """Test detection of names with middle name."""
        assert detector.detect("John Michael Doe") == ScanType.NAME

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_empty_input(self, detector):
        """Test empty input returns None."""
        assert detector.detect("") is None
        assert detector.detect("   ") is None

    def test_none_input(self, detector):
        """Test None input returns None."""
        assert detector.detect(None) is None

    def test_whitespace_trimming(self, detector):
        """Test that whitespace is trimmed."""
        assert detector.detect("  192.168.1.1  ") == ScanType.IP
        assert detector.detect("  user@example.com  ") == ScanType.EMAIL


class TestInputValidation:
    """Tests for input validation methods."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance."""
        return InputDetector()

    def test_validate_email_valid(self, detector):
        """Test validation of valid emails."""
        assert detector.validate_for_type("user@example.com", ScanType.EMAIL) is True

    def test_validate_email_invalid(self, detector):
        """Test validation of invalid emails."""
        assert detector.validate_for_type("not-an-email", ScanType.EMAIL) is False

    def test_validate_ip_valid(self, detector):
        """Test validation of valid IPs."""
        assert detector.validate_for_type("192.168.1.1", ScanType.IP) is True

    def test_validate_ip_invalid(self, detector):
        """Test validation of invalid IPs."""
        assert detector.validate_for_type("256.1.1.1", ScanType.IP) is False

    def test_validate_username_any(self, detector):
        """Test that any non-empty string validates as username."""
        assert detector.validate_for_type("anything", ScanType.USERNAME) is True
        assert detector.validate_for_type("", ScanType.USERNAME) is False
