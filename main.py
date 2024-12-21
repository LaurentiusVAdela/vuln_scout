import argparse
import sys
import json

# Import the required functions/classes from your local package
from vuln_scout.parser import parse_requirements
from vuln_scout.fetcher import fetch_vulnerabilities
from vuln_scout.utils import version_in_vulnerable_range, meets_minimum_severity
from vuln_scout.report import generate_markdown_report


def main():
    parser = argparse.ArgumentParser(description="VulnScout: Dependency Vulnerability Scanner")
    parser.add_argument("--input", '-i', required=True, help="Path to the requirements.txt file")
    parser.add_argument("--output", '-o', default="report.md", help="Output report file (default: report.md)")
    parser.add_argument("--format", '-f', default='md', choices=['md', 'json'], help="Report format")
    parser.add_argument(
        "--min-severity", 
        type=float, 
        default=0.0,
        help="Minimum severity threshold (CVSS) to report (default: 0.0)"
    )

    args = parser.parse_args()

    # Parse dependencies
    deps = parse_requirements(args.input)
    print("Parsed dependencies:", deps)

    # Create a dictionary to store results for each dependency
    all_results = {}

    # Fetch and filter vulnerabilities for each dependency
    for dep in deps:
        name = dep["name"]
        version = dep["version"]

        raw_vulns = fetch_vulnerabilities(name, version)

        filtered_vulns = []
        for vuln in raw_vulns:
            in_affected_range = any(
                version_in_vulnerable_range(version, [r])
                for r in vuln["affected_ranges"]
            )
            # Only include vulnerabilities that affect this version AND meet the min severity
            if in_affected_range and meets_minimum_severity(vuln, args.min_severity):
                filtered_vulns.append(vuln)

        all_results[name] = {
            "version": version,
            "vulnerabilities": filtered_vulns
        }

    # Generate the final report in the requested format
    if args.format == "md":
        report_content = generate_markdown_report(all_results)
    else:  # 'json'
        report_content = json.dumps(all_results, indent=2)

    # Write the report to the output file
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(report_content)

    print(f"\nReport generated: {args.output}")


if __name__ == "__main__":
    main()
