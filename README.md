## TrustVault

Secure document sharing with role-based access control and an audit trail.
Built with Python, Flask and SQLite.

**Live site:** https://trustvault-sushma.onrender.com
Demo accounts (admin1, owner1, viewer1) and their password are in my submission form.

## What it does
- Three roles: admin, owner, viewer
- Owners upload documents and grant or revoke read/edit access to named users
- One function, `get_access()`, decides every document request. It reads the database each time, so a revoke works on the next request
- Every upload, download, grant, revoke and refused attempt is written to an audit log
- Admins see the audit log but cannot open a document without a grant
- Search by name, owner, category and date, limited to documents the user can access

## Run it locally (Windows PowerShell)
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    $env:DEMO_PASSWORD="choose-a-password-10-chars-or-more"
    python app.py

Open http://127.0.0.1:5000 and log in as admin1, owner1 or viewer1 with that password.

## Run the tests
    pip install pytest
    python -m pytest -q

## Files
- `app.py`: the application
- `schema.sql`: database tables
- `PERMISSIONS.md`: the permission rules
- `THREATS.md`: threats and mitigations
- `PROMPTS.md`: where the AI was wrong and what I did
- `tests/test_access.py`: automated access control tests

## Not finished
- No CSRF protection on forms yet

- Upload checks the file extension only, not the real file content
- The "edit" access level can be granted but is not used by any feature yet
- The free server resets uploaded files and the database when it restarts trustvault
Secure document sharing platform with role-based access control and a tamper-evident audit trail
