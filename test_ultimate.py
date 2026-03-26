import asyncio
import aiohttp
import json
import time

async def test_api():
    url = "http://localhost:8000/api/v1/analyze/url"
    test_urls = [
        "http://login-secure-verify.xn--test.com/update", # Benchmark CRITICAL
        "https://google.com" # Benchmark CLEAN
    ]
    
    async with aiohttp.ClientSession() as session:
        for target in test_urls:
            print(f"\n--- Testing: {target} ---")
            start = time.time()
            try:
                async with session.post(url, json={"url": target}) as resp:
                    print(f"Status: {resp.status}")
                    if resp.status == 200:
                        data = await resp.json()
                        print(json.dumps(data, indent=2))
                    else:
                        text = await resp.text()
                        print("Error:", text)
            except Exception as e:
                print("Connection Failed:", e)
            print(f"Time Taken: {time.time() - start:.2f}s")

if __name__ == "__main__":
    asyncio.run(test_api())
