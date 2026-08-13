"""Tests for SSRF protection."""

import pytest

from app.security.ssrf import SSRFError, is_blocked_hostname, is_blocked_ip, resolve_and_validate


class TestSSRFProtection:
    def test_block_localhost(self):
        blocked, reason = is_blocked_hostname("localhost")
        assert blocked is True

    def test_block_private_ip_10(self):
        blocked, reason = is_blocked_ip("10.0.0.1")
        assert blocked is True
        assert "Private" in reason

    def test_block_private_ip_172(self):
        blocked, _ = is_blocked_ip("172.16.0.1")
        assert blocked is True

    def test_block_private_ip_192(self):
        blocked, _ = is_blocked_ip("192.168.1.1")
        assert blocked is True

    def test_block_loopback(self):
        blocked, reason = is_blocked_ip("127.0.0.1")
        assert blocked is True
        assert "Loopback" in reason

    def test_block_metadata_endpoint(self):
        blocked, _ = is_blocked_ip("169.254.169.254")
        assert blocked is True

    def test_block_ipv6_loopback(self):
        blocked, _ = is_blocked_ip("::1")
        assert blocked is True

    def test_block_link_local(self):
        blocked, _ = is_blocked_ip("169.254.1.1")
        assert blocked is True

    def test_allow_public_ip(self):
        blocked, _ = is_blocked_ip("8.8.8.8")
        assert blocked is False

    def test_block_internal_tld(self):
        blocked, _ = is_blocked_hostname("server.internal")
        assert blocked is True

    def test_block_cgnat(self):
        blocked, _ = is_blocked_ip("100.64.0.1")
        assert blocked is True

    @pytest.mark.asyncio
    async def test_resolve_public_domain(self):
        result = await resolve_and_validate("example.com")
        assert len(result.ip_addresses) > 0

    @pytest.mark.asyncio
    async def test_resolve_localhost_blocked(self):
        with pytest.raises(SSRFError):
            await resolve_and_validate("localhost")

    @pytest.mark.asyncio
    async def test_resolve_private_ip_blocked(self):
        with pytest.raises(SSRFError):
            await resolve_and_validate("127.0.0.1")
