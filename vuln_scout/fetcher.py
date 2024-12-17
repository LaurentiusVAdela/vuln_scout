import requests
import time
from vuln_scout.cache import get_cached_vulnerabilities, set_cached_vulnerabilities

OSV_API_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package_name: str, package_version: str, max_retries=3, backoff_factor=2):
    """Fetch vulnerabilities from OSV for a given Python package and version with caching and retries."""

    # Check cache first
    cached = get_cached_vulnerabilities(package_name, package_version)
    if cached is not None:
        return cached  # Return cached results directly

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": package_version
    }

    attempt = 0
    while attempt < max_retries:
        try:
            response = requests.post(OSV_API_URL, json=payload, timeout=10)
            # If request failed with a non-2xx status code, raise for handling
            if response.status_code != 200:
                response.raise_for_status()

            data = response.json()
            vulns = data.get("vulns", [])

            results = []
            for vuln in vulns:
                vuln_id = vuln.get("id", "N/A")
                summary = vuln.get("summary", "No summary available")
                affected_ranges = []
                for aff in vuln.get("affected", []):
                    for r in aff.get("ranges", []):
                        affected_ranges.append({
                            "type": r.get("type", "N/A"),
                            "events": r.get("events", [])
                        })

                severity_info = vuln.get("severity", [])
                severity_score = severity_info[0].get("score", "N/A") if severity_info else "N/A"

                results.append({
                    "id": vuln_id,
                    "summary": summary,
                    "severity": severity_score,
                    "affected_ranges": affected_ranges,
                    "references": vuln.get("references", [])
                })

            # Save to cache before returning
            set_cached_vulnerabilities(package_name, package_version, results)
            return results

        except requests.exceptions.HTTPError as e:
            # Handle rate limit or transient server errors by retrying
            status_code = e.response.status_code
            if status_code == 429 or 500 <= status_code < 600:
                attempt += 1
                sleep_time = backoff_factor ** attempt
                print(f"Error {status_code}: Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                # For non-retryable errors, re-raise the exception
                raise
        except requests.exceptions.RequestException as e:
            # Covers all other request-related errors (network issues, etc.)
            attempt += 1
            sleep_time = backoff_factor ** attempt
            print(f"Network error: {e}. Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)

    # If we exit the loop, all retries failed
    print(f"Failed to fetch vulnerabilities for {package_name}=={package_version} after {max_retries} retries.")
    return []
