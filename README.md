# Vuln Scout – Python Package Vulnerability Scanner

**A simple web app to detect known vulnerabilities in Python packages using Flask and public vulnerability data sources.**

## How It Works

- User enters a Python package name (e.g., `requests`)
- App queries public vulnerability APIs (like OSV, Safety DB, or NVD)
- Displays vulnerability details: ID, severity, description, and fix info

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite for caching results
- **Dependency Fetching**: Python API requests to vulnerability databases
- **Frontend**: HTML + Bootstrap
