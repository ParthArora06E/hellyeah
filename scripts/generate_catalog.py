import json

with open("output/ranked_ips.json", "r", encoding="utf-8") as f:
    data = json.load(f)

items = data["items"]

code = f'''"""
Curated User Proxy Pool (100 High-Anonymity Verified Proxies)
"""
from typing import List, Dict, Any

USER_PROXIES: List[Dict[str, Any]] = {json.dumps(items, indent=2)}

def get_user_proxies() -> List[Dict[str, Any]]:
    return list(USER_PROXIES)

def get_user_ips() -> List[str]:
    return [p["ip"] for p in USER_PROXIES]

def get_user_proxy_urls() -> List[str]:
    return [p["proxy_url"] for p in USER_PROXIES]
'''

with open("backend/app/core/user_proxies_data.py", "w", encoding="utf-8") as f:
    f.write(code)

with open("output/user_proxies.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Generated backend/app/core/user_proxies_data.py with {len(items)} proxies")
