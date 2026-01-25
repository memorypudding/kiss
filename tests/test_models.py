"""Tests for data models."""

import pytest

from xsint.constants import ScanStatus, ScanType
from xsint.models import ScanResult, ScanReport, InfoRow


class TestScanResult:
    """Tests for ScanResult model."""

    def test_create_found_result(self):
        """Test creating a FOUND result."""
        result = ScanResult.found("HIBP", "Found 3 breaches")

        assert result.service == "HIBP"
        assert result.status == ScanStatus.FOUND
        assert result.details == "Found 3 breaches"
        assert result.is_found is True
        assert result.is_error is False
        assert result.is_clean is False

    def test_create_clean_result(self):
        """Test creating a CLEAN result."""
        result = ScanResult.clean("HIBP", "No breaches found")

        assert result.status == ScanStatus.CLEAN
        assert result.is_clean is True
        assert result.is_found is False

    def test_create_error_result(self):
        """Test creating an ERROR result."""
        result = ScanResult.error("HIBP", "Connection failed")

        assert result.status == ScanStatus.ERROR
        assert result.is_error is True
        assert result.color == "red"

    def test_create_skipped_result(self):
        """Test creating a SKIPPED result."""
        result = ScanResult.skipped("HIBP", "API key missing")

        assert result.status == ScanStatus.SKIPPED
        assert result.color == "yellow"

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = ScanResult.found("HIBP", "Found breaches")
        d = result.to_dict()

        assert d["service"] == "HIBP"
        assert d["status"] == "Found"
        assert d["details"] == "Found breaches"
        assert d["color"] == "green"

    def test_to_table_row(self):
        """Test converting result to table row format."""
        result = ScanResult.error("HIBP", "Error message")
        row = result.to_table_row()

        assert row["label"] == "HIBP"
        assert row["val"] == "Error message"
        assert row["color"] == "red"

    def test_with_raw_data(self):
        """Test result with raw API data."""
        raw = {"breaches": [{"Name": "Test"}]}
        result = ScanResult.found("HIBP", "1 breach", raw_data=raw)

        assert result.raw_data == raw


class TestScanReport:
    """Tests for ScanReport model."""

    def test_create_report(self):
        """Test creating a scan report."""
        report = ScanReport(target="test@example.com", scan_type=ScanType.EMAIL)

        assert report.target == "test@example.com"
        assert report.scan_type == ScanType.EMAIL
        assert len(report.results) == 0

    def test_add_result(self):
        """Test adding a single result."""
        report = ScanReport(target="test@example.com", scan_type=ScanType.EMAIL)
        result = ScanResult.found("HIBP", "Found")

        report.add_result(result)

        assert len(report.results) == 1
        assert report.results[0] == result

    def test_add_results(self):
        """Test adding multiple results."""
        report = ScanReport(target="test@example.com", scan_type=ScanType.EMAIL)
        results = [
            ScanResult.found("HIBP", "Found"),
            ScanResult.clean("Gravatar"),
        ]

        report.add_results(results)

        assert len(report.results) == 2

    def test_has_findings(self):
        """Test has_findings property."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)

        assert report.has_findings is False

        report.add_result(ScanResult.found("HIBP", "Found"))
        assert report.has_findings is True

    def test_has_errors(self):
        """Test has_errors property."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)

        assert report.has_errors is False

        report.add_result(ScanResult.error("HIBP", "Error"))
        assert report.has_errors is True

    def test_findings_count(self):
        """Test findings count."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)
        report.add_results([
            ScanResult.found("A", "Found"),
            ScanResult.clean("B"),
            ScanResult.found("C", "Found"),
        ])

        assert report.findings_count == 2

    def test_errors_count(self):
        """Test errors count."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)
        report.add_results([
            ScanResult.error("A", "Error"),
            ScanResult.clean("B"),
            ScanResult.error("C", "Error"),
        ])

        assert report.errors_count == 2

    def test_to_table_rows(self):
        """Test converting all results to table rows."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)
        report.add_results([
            ScanResult.found("A", "Found"),
            ScanResult.clean("B"),
        ])

        rows = report.to_table_rows()

        assert len(rows) == 2
        assert rows[0]["label"] == "A"
        assert rows[1]["label"] == "B"

    def test_get_title(self):
        """Test getting appropriate title."""
        report = ScanReport(target="test", scan_type=ScanType.EMAIL)
        assert report.get_title() == "EMAIL ANALYSIS"

        report = ScanReport(target="test", scan_type=ScanType.IP)
        assert report.get_title() == "IP INTELLIGENCE"

    def test_metadata(self):
        """Test metadata storage."""
        report = ScanReport(target="test", scan_type=ScanType.PHONE)
        report.metadata["phone_formatted"] = "+1 234 567 8900"

        assert report.metadata["phone_formatted"] == "+1 234 567 8900"


class TestInfoRow:
    """Tests for InfoRow model."""

    def test_create_info_row(self):
        """Test creating an info row."""
        row = InfoRow(label="City", value="Boston")

        assert row.label == "City"
        assert row.value == "Boston"
        assert row.color == "white"

    def test_create_with_color(self):
        """Test creating with custom color."""
        row = InfoRow(label="Status", value="Valid", color="green")

        assert row.color == "green"

    def test_to_table_row(self):
        """Test converting to table row format."""
        row = InfoRow(label="Region", value="US East", color="cyan")
        table_row = row.to_table_row()

        assert table_row["label"] == "Region"
        assert table_row["val"] == "US East"
        assert table_row["color"] == "cyan"
