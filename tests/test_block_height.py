#!/usr/bin/env python3
"""Test block-height endpoint."""

import requests
import json

BASE_URL = "http://127.0.0.1:8101"

print("\n" + "=" * 60)
print("TEST: Get Block Height")
print("=" * 60)

try:
    response = requests.get(f"{BASE_URL}/block-height")
    print(f"Status: {response.status_code}")
    print(f"Response:\n{json.dumps(response.json(), indent=2)}")

    if response.status_code == 200:
        data = response.json()
        if "height" in data and "last_update" in data:
            print("\n✓ Block height request succeeded")
        else:
            print("\n✗ Missing expected fields")
    else:
        print(f"\n✗ Block height request failed")
except Exception as e:
    print(f"\n✗ Error: {e}")

print("=" * 60 + "\n")
