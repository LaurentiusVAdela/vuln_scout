import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities(package_name: str, package_version: str):
    """Fetch vulnerabilities from OSV for a given Python package and version."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": package_version
    }

    response = requests.post(OSV_API_URL, json=payload)
    response.raise_for_status()  # Raises an HTTPError if status != 200

    data = response.json()

    # OSV returns a JSON like:
    # {
    #   "vulns": [
    #     {
    #       "id": "OSV-2021-...",
    #       "affected": [...],
    #       "severity": [...],
    #       "references": [...],
    #       ...
    #     },
    #     ...
    #   ]
    # }

    vulns = data.get("vulns", [])
    results = []

    for vuln in vulns:
        # Extract useful information
        vuln_id = vuln.get("id", "N/A")
        summary = vuln.get("summary", "No summary available")
        affected_ranges = []
        
        # "affected" might contain version ranges
        for aff in vuln.get("affected", []):
            # Each 'aff' might have "ranges" and "versions"
            # We'll collect the ranges of vulnerable versions
            for r in aff.get("ranges", []):
                affected_ranges.append({
                    "type": r.get("type", "N/A"),
                    "events": r.get("events", [])
                })

        # Severity information might be present in "severity" field
        # According to OSV, severity might be a list of objects with "type" and "score"
        severity_info = vuln.get("severity", [])
        # Just pick the first severity score if it exists, or default
        if severity_info:
            severity_score = severity_info[0].get("score", "N/A")
        else:
            severity_score = "N/A"

        results.append({
            "id": vuln_id,
            "summary": summary,
            "severity": severity_score,
            "affected_ranges": affected_ranges,
            "references": vuln.get("references", [])
        })

    return results
