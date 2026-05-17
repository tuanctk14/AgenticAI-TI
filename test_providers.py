#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test CISA KEV and Vulners connectivity"""
import asyncio
from tools.providers import KEVProvider, VulnersProvider

async def test_kev():
    """Test CISA KEV provider"""
    print("=" * 60)
    print("TEST 1: CISA KEV Provider")
    print("=" * 60)

    kev = KEVProvider()

    # Test connection
    print("\n1. Testing connection...")
    is_connected = await kev.validate_connection()
    print(f"   Connection: {'✓ OK' if is_connected else '✗ FAILED'}")

    # Test fetch CVE that should be in KEV
    print("\n2. Testing fetch (CVE-2021-44228 - known exploited)...")
    result = await kev.fetch_with_timeout("CVE-2021-44228")
    if result.success:
        print(f"   ✓ Found in KEV")
        data = result.data
        print(f"     - Listed: {data.get('listed')}")
        print(f"     - Date Added: {data.get('date_added')}")
        print(f"     - Source: {data.get('source')}")
    else:
        print(f"   ✗ Not in KEV or error: {result.error}")

    # Test fetch CVE that should NOT be in KEV
    print("\n3. Testing fetch (CVE-2024-99999 - likely not exploited)...")
    result = await kev.fetch_with_timeout("CVE-2024-99999")
    if result.success:
        print(f"   ✓ Found: Listed={result.data.get('listed')}")
    else:
        print(f"   ✗ Not found (expected): {result.error}")


async def test_vulners():
    """Test Vulners provider"""
    print("\n" + "=" * 60)
    print("TEST 2: Vulners Provider")
    print("=" * 60)

    vulners = VulnersProvider()

    # Test connection
    print("\n1. Testing connection...")
    is_connected = await vulners.validate_connection()
    print(f"   Connection: {'✓ OK' if is_connected else '✗ FAILED'}")

    # Test fetch CVE with known exploits
    print("\n2. Testing fetch (CVE-2021-44228 - Log4Shell)...")
    result = await vulners.fetch_with_timeout("CVE-2021-44228")
    if result.success:
        data = result.data
        print(f"   ✓ Success")
        print(f"     - Public Exploit: {data.get('public_exploit_available')}")
        print(f"     - Metasploit: {data.get('metasploit_available')}")
        print(f"     - Exploit Count: {data.get('exploit_count')}")
        print(f"     - Sources: {data.get('exploit_sources', [])[:3]}")
    else:
        print(f"   ✗ Error: {result.error}")

    # Test another CVE
    print("\n3. Testing fetch (CVE-2020-37244)...")
    result = await vulners.fetch_with_timeout("CVE-2020-37244")
    if result.success:
        data = result.data
        print(f"   ✓ Success")
        print(f"     - Public Exploit: {data.get('public_exploit_available')}")
        print(f"     - Exploit Count: {data.get('exploit_count')}")
    else:
        print(f"   ✗ Error: {result.error}")


async def main():
    await test_kev()
    await test_vulners()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("✓ Tests completed. Check results above.")


if __name__ == "__main__":
    asyncio.run(main())
