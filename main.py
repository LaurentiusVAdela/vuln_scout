import argparse
import sys

from vuln_scout.parser import parse_requirements
from vuln_scout.fetcher import fetch_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="VulnScout: Dependency Vulnerability Scanner")
    parser.add_argument("--input", '-i', required=True, help="Path to the requirements.txt file")
    parser.add_argument("--output", '-o', default="report.md", help="Output report file (default: report.md)")
    parser.add_argument("--format", '-f', default='md', choices=['md', 'json'], help="Report format")

    args = parser.parse_args()

    # Parse dependencies
    deps = parse_requirements(args.input)
    print("Parsed dependencies:", deps)

    # Fetch vulnerabilities for each dependency
    all_results = {}
    for dep in deps:
        name = dep["name"]
        version = dep["version"]
        vulns = fetch_vulnerabilities(name, version)
        all_results[name] = {
            "version": version,
            "vulnerabilities": vulns
        }

    # For now, just print the results to verify
    print("Vulnerability Results:")
    for pkg, info in all_results.items():
        print(f"Package: {pkg}=={info['version']}")
        if info["vulnerabilities"]:
            for v in info["vulnerabilities"]:
                print(f"  - {v['id']}: {v['summary']} (Severity: {v['severity']})")
        else:
            print("  No vulnerabilities found.")

if __name__=="__main__":
    main()
