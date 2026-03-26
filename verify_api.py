import requests

def test_url_analysis():
    print("Testing URL Analysis...")
    url = "http://127.0.0.1:8000/api/analyze-url"
    payload = {"url": "http://login-secure-verify.xn--test.com/update"}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        print(f"Success! Score: {result['score']}, Risk: {result['risk']}")
        print(f"Indicators: {result['indicators']}")
    except Exception as e:
        print(f"URL Analysis Failed: {e}")

if __name__ == "__main__":
    # Note: Backend must be running
    try:
        test_url_analysis()
    except Exception as e:
        print(f"Verification script error: {e}")
