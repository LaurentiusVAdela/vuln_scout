import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="VulnScout: Dependency Vulnerability Scanner")
    parser.add_argument("--input", '-i', required=True, help="Path to the requirements.txt file")
    parser.add_argument("--output", '-o', default="report.md", help="Output report file (default: report.md)")
    parser.add_argument("--format", '-f', default='md', choices=['md', 'json'], help="Report format")

    args = parser.parse_args()

    print(f"Input file: {args.input}")
    print(f"Output file: {args.output}")
    print(f"Report format: {args.format}")

if __name__=="__main__":
    main()
