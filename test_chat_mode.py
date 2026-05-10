#!/usr/bin/env python3
"""Test script for menu 4 chat mode"""
import sys
import os
import subprocess

# Fix encoding on Windows
if sys.platform == "win32":
    import codecs
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def test_chat():
    """Simulate interactive chat by running multiple queries"""
    queries = [
        "bạn biết karina không",
        "tôi muốn hỏi về log4j",
        "CVE-2021-44228 ảnh hưởng thiết bị nào",
        "thông tin thiết bị",
    ]

    print("\n=== TESTING MENU 4 CHAT MODE ===\n")

    for query in queries:
        print(f"\nBạn: {query}")
        print("-" * 60)

        # Run single query
        result = subprocess.run(
            [sys.executable, "main.py", "--query", query],
            capture_output=True,
            text=True,
        )

        # Extract response from output
        output = result.stdout
        if "ANSWER:" in output:
            lines = output.split("\n")
            for i, line in enumerate(lines):
                if "ANSWER:" in line:
                    # Print from ANSWER onwards (skip the structure output)
                    answer_idx = line.index("ANSWER:")
                    answer_text = line[answer_idx + 8:].strip()
                    if answer_text:
                        print(f"ATI: {answer_text}")
                    break

        print()

if __name__ == "__main__":
    test_chat()
