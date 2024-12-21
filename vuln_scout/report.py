def generate_markdown_report(results):
    """
    results is a dict like:
    {
      "requests": {
        "version": "2.19.1",
        "vulnerabilities": [
          {
            "id": ...,
            "summary": ...,
            "severity": ...,
            "affected_ranges": [...],
            "references": [...]
          },
          ...
        ]
      },
      ...
    }

    Returns a string containing Markdown content.
    """

    lines = ["# Vulnerability Report\n"]

    for pkg, info in results.items():
        version = info["version"]
        vulns = info["vulnerabilities"]

        if vulns:
            lines.append(f"## {pkg}=={version}\n")
            for vuln in vulns:
                lines.append(f"**ID**: {vuln['id']}  \n")
                lines.append(f"**Severity**: {vuln['severity']}  \n")
                lines.append(f"**Summary**: {vuln['summary']}  \n")
                lines.append(f"**Affected Ranges**: {vuln['affected_ranges']}  \n")
                lines.append("---\n")
        else:
            # No vulnerabilities
            lines.append(f"## {pkg}=={version}\n")
            lines.append("No known vulnerabilities found.\n")
            lines.append("---\n")

    return "\n".join(lines)
