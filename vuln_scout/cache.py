import json
import os

CACHE_FILE = "cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache_data, f, indent=2)

def get_cached_vulnerabilities(package_name, package_version):
    cache = load_cache()
    pkg_key = f"{package_name}=={package_version}"
    return cache.get(pkg_key)

def set_cached_vulnerabilities(package_name, package_version, vulnerablilities):
    cache = load_cache()
    pkg_key = f"{package_name}=={package_version}"
    cache[pkg_key] = vulnerablilities
    save_cache(cache)
    