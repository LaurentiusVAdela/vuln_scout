import argparse
import sys
import json

from vuln_scout.parser import parse_requirements
from vuln_scout.fetcher import fetch_vulnerabilities
from vuln_scout.utils import version_in_vulnerable_range
from vuln_scout.report import generate_markdown_report

def main():
    parser = argparse.ArgumentParser(description="VulnScout: Dependency Vulnerability Scanner")
    parser.add_argument("--input", '-i', required=True, help="Path to the requirements.txt file")
    parser.add_argument("--output", '-o', default="report.md", help="Output report file (default: report.md)")
    parser.add_argument("--format", '-f', default='md', choices=['md', 'json'], help="Report format")

    args = parser.parse_args()

    # Parse dependencies
    deps = parse_requirements(args.input)
    print("Parsed dependencies:", deps)

    # Fetch and filter vulnerabilities
    all_results = {}
    for dep in deps:
        name = dep["name"]
        version = dep["version"]
        raw_vulns = fetch_vulnerabilities(name, version)

        filtered_vulns = []
        for vuln in raw_vulns:
            # Check if the current version is within the affected ranges
            if any(version_in_vulnerable_range(version, [r]) for r in vuln["affected_ranges"]):
                filtered_vulns.append(vuln)

        all_results[name] = {
            "version": version,
            "vulnerabilities": filtered_vulns
        }

    # Optional: Print filtered results in the console for debugging
    print("\nFiltered Vulnerability Results:")
    for pkg, info in all_results.items():
        print(f"Package: {pkg}=={info['version']}")
        vulns = info["vulnerabilities"]
        if not vulns:
            print("  No vulnerabilities found.")
        else:
            for v in vulns:
                print(f"  - {v['id']}: {v['summary']} (Severity: {v['severity']})")

    # Generate final report
    if args.format == "md":
        report_content = generate_markdown_report(all_results)
    else:  # json
        report_content = json.dumps(all_results, indent=2)

    # Write report to file
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report_content)

    print(f"\nReport generated: {args.output}")

if __name__ == "__main__":
    main()
