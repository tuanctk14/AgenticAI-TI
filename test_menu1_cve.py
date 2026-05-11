#!/usr/bin/env python3
"""Test Menu 1: CVE Scan"""
import sys
import os

if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(__file__))

from main import run_query, _print_summary

def test():
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║           MENU 1: CVE SCAN TEST                        ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    query = "Hãy quét lỗ hổng (keyword: apache) từ NVD, so khớp với thiết bị nội bộ và cho biết thiết bị nào bị ảnh hưởng."
    print(f"Query: {query}\n")

    result = run_query(query, verbose=True, chat_mode=False)
    return result

if __name__ == "__main__":
    test()
