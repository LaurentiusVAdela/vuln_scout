import requests
import time

OSV_API_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package_name: str, package_version: str, max_retries=3, backoff_factor=2):
    """Fetch vulnerabilities from OSV for a given Python package and version with caching and retries."""
    
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

                # We look at all severity entries, pick or compute the highest
                severity_info = vuln.get("severity", [])
                scores = []
                for s in severity_info:
                    score_str = s.get("score", "N/A")
                    try:
                        scores.append(float(score_str))
                    except ValueError:
                        # If not numeric, ignore
                        pass

                if scores:
                    severity_score = max(scores)  # Use the highest severity found
                else:
                    severity_score = "N/A"

                results.append({
                    "id": vuln_id,
                    "summary": summary,
                    "severity": severity_score,  # Could be float or "N/A"
                    "affected_ranges": affected_ranges,
                    "references": vuln.get("references", [])
                })

            return results

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 429 or 500 <= status_code < 600:
                attempt += 1
                sleep_time = backoff_factor ** attempt
                print(f"Error {status_code}: Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                raise
        except requests.exceptions.RequestException as e:
            attempt += 1
            sleep_time = backoff_factor ** attempt
            print(f"Network error: {e}. Retrying in {sleep_time} seconds...")
            time.sleep(sleep_time)

    print(f"Failed to fetch vulnerabilities for {package_name}=={package_version} after {max_retries} retries.")
    return []
