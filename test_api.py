import requests
import json

def test_url_scan():
    url = "http://example.com"
    try:
        response = requests.post("http://localhost:5000/analyze/url", json={"url": url})
        print(f"URL Scan Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("This script assumes the app is running on http://localhost:5000")
    # test_url_scan()
