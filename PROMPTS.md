# PROMPTS.md

## Entry 1: 2 Nov 2026
**What I asked:** Build register and login with roles, document upload with validation, and download, share and revoke where one function decides access.

**What the AI produced:** A Flask app where every document request calls `get_access()`, which reads the database each time. Refused attempts are written to the audit log.

**How I checked it:**
- As viewer1 before any grant, the download URL gave 404.
- After the owner granted read access, viewer1 could download.
- After the owner revoked access, the very next request gave 404.
- The audit log has the grant, the revoke and the refused download (row 25).

**Gaps I found in the AI's code (not fixed yet):**
1. Forms have no CSRF protection, so another website could trick a logged-in owner into sharing a file.
2. The `edit` level can be granted, but no part of the app uses it yet.
3. There is no limit on login attempts.
4. Upload checks only the file extension, not the real file content.
5. `debug=True` must be turned off before deployment.

**What I will do:** Fix these in later commits and write each fix as its own entry.