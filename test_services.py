import sys
import json
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from services.url_service import analyze_url_heuristics
from services.binary_service import analyze_binary

def test_url():
    print("--- URL Test 1 ---")
    res1 = analyze_url_heuristics("http://192.168.1.1/login.php?update=true")
    print(json.dumps(res1, indent=2))
    
    print("--- URL Test 2 ---")
    res2 = analyze_url_heuristics("https://google.com")
    print(json.dumps(res2, indent=2))

def test_binary():
    print("--- Binary Test ---")
    # Create a dummy PE file bytes array
    dummy_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00" \
               b"Some random strings here http://malicious-domain.com cmd.exe powershell.exe " \
               b"A" * 1000
    res = analyze_binary(dummy_pe, "fake_malware.exe")
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    test_url()
    test_binary()
