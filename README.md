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

## Usage

1. Clone the repo  
2. Run `pip install -r requirements.txt`  
3. Start with `python app.py`  
4. Browse to `http://localhost:5000` and enter a Python package name  
5. View the vulnerability scan results

## Security Best Practices

- ✅ Input sanitization to prevent injection  
- ✅ Parameterized queries for database safety  
- ✅ HTTPS configuration (if added)
