#!/usr/bin/env python3
"""Test Menu 2: Report Generation"""
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
    print("║           MENU 2: REPORT GENERATION TEST               ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    query = "Thực hiện đánh giá CVE: lấy CVE severity HIGH từ NVD, so khớp với hệ thống nội bộ, tạo báo cáo executive_summary."
    print(f"Query: {query}\n")
    print("Note: This should generate and display a report file\n")

    result = run_query(query, verbose=True, chat_mode=False)
    return result

if __name__ == "__main__":
    test()
