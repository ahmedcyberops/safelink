"""Tests for URL parser."""

import pytest

from app.security.url_parser import URLValidationError, parse_url


class TestURLParser:
    def test_valid_https_url(self):
        result = parse_url("https://example.com/path?q=1")
        assert result.scheme == "https"
        assert result.host == "example.com"
        assert result.path == "/path"

    def test_adds_scheme_if_missing(self):
        result = parse_url("example.com")
        assert result.scheme == "https"
        assert result.host == "example.com"

    def test_malformed_url(self):
        with pytest.raises(URLValidationError):
            parse_url("")

    def test_unsupported_scheme(self):
        with pytest.raises(URLValidationError) as exc:
            parse_url("ftp://example.com")
        assert exc.value.code == "unsupported_scheme"

    def test_localhost_blocked_at_parse(self):
        result = parse_url("http://localhost:8080")
        assert result.host == "localhost"

    def test_private_ip_detection(self):
        result = parse_url("http://192.168.1.1/admin")
        assert result.is_ip_host is True
        assert result.ip_address == "192.168.1.1"

    def test_ipv6_detection(self):
        result = parse_url("http://[::1]/")
        assert result.is_ip_host is True

    def test_encoded_ip_decimal(self):
        result = parse_url("http://2130706433/")
        assert result.is_ip_host is True
        assert result.ip_address == "127.0.0.1"

    def test_userinfo_rejected(self):
        with pytest.raises(URLValidationError) as exc:
            parse_url("http://user:pass@example.com")
        assert exc.value.code == "userinfo_not_allowed"

    def test_non_standard_port(self):
        result = parse_url("http://example.com:8080/path")
        assert result.port == 8080

    def test_url_too_long(self):
        with pytest.raises(URLValidationError) as exc:
            parse_url("https://example.com/" + "a" * 3000)
        assert exc.value.code == "url_too_long"

    def test_shortener_detection(self):
        result = parse_url("https://bit.ly/abc123")
        assert result.is_shortener is True

    def test_encoding_detection(self):
        result = parse_url("https://example.com/%70ath")
        assert "percent_encoding" in result.encoding_indicators
