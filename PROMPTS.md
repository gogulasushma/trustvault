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

## Entry 2: 2 Nov 2026
**What I asked:** Write automated tests proving that one user cannot reach another user's documents.

**What the AI produced:** 14 pytest tests using a temporary database, covering no-login, no-grant, other owner, admin without grant, grant, revoke, search, upload and admin page.

**What was wrong:** The AI told me there were 13 tests, but pytest collected 14. I trusted the pytest output instead of the AI's number.

**How I checked the tests are meaningful:** I commented out the permission check in the `download` route on purpose. Several tests failed, including the revoke test. Then I restored the file with `git checkout app.py` and all 14 passed again.

## Entry 3: 6 Nov 2026
**What I asked:** Add a limit on failed login attempts.

**What the AI produced:** A check in the login route that counts failed logins for a username in the last 15 minutes. After 5 failures, login is refused for that username.

**What I checked:** I added a test that makes 5 wrong logins and then tries the correct password. The test expects the "Too many failed attempts" message and no login. All 15 tests pass.

**Problem I found in the design:** The limit counts attempts per username, not per person. Anyone can lock the admin1 account for 15 minutes by typing wrong passwords on purpose. I decided to keep it and write this in THREATS.md as a known trade-off.

## Entry 4: 6 Nov 2026
**What I asked:** Add CSRF protection, so another website cannot make a logged-in user press Share, Revoke or Log out without knowing.

**What the AI produced:** A random token stored in the user's session, a hidden `csrf_token` field in every form, and a check that rejects any POST request without the right token with a 400 error.

**What I had to change:** The 14 old tests sent forms without a token, so they would have failed. The test file was rewritten to send a token like a real browser. I also had to update five templates, because a form without the token field would be rejected.

**How I checked it:** I added a test that posts a login without a token and expects a 400 error. All 16 tests pass. On my computer I tested Share, Revoke and Log out.

**Not covered:** The token is created once per session and does not change after each request. It protects POST forms only.

## Entry 5: 6 Nov 2026
**What was wrong:** The first version of THREATS.md called the audit log "immutable" and "searchable". Neither is true for my app. Anyone with direct access to the database file can edit or delete rows, and the admin page only shows the latest 100 events with no search. It also said the session cookie "completely" blocks JavaScript, but the HttpOnly flag only stops JavaScript from reading the cookie.

**What I did instead:** I rewrote THREATS.md so that every claim matches the code. The audit log is now described as append-only and not tamper-proof, and each section lists what is still open. I did this because the judges mark claims that do not match the code.