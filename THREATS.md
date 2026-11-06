# THREATS.md: Threats and what TrustVault does about them

This file lists the ways TrustVault could be attacked, what is built to stop each one, and what is still open. Where something is not fully solved, it says so.

---

## 1. Reading another user's document (guessing a document number)
* **Threat:** A logged-in user changes the number in `/documents/<id>/download` to try to open files that belong to someone else.
* **What is built:** Every document route calls one function, `get_access()`. It reads the database on each request and allows the request only if the user owns the document or has a grant for it. Otherwise the server answers `404 Not Found`, the same answer as for a document that does not exist, so a stranger cannot tell which numbers are real. A refused attempt is written to the audit log.
* **Tests:** `test_viewer_without_grant_is_refused`, `test_other_owner_cannot_reach_document`, `test_admin_cannot_read_document_without_grant`, `test_grant_to_one_user_does_not_help_another`.
* **Still open:** Document numbers are 1, 2, 3 in order, so they are easy to guess. Guessing only leads to a refusal and a log entry, but random IDs would be better.

## 2. Opening the admin page without being an admin
* **Threat:** A viewer or owner types `/admin` into the address bar.
* **What is built:** The route is wrapped by `role_required("admin")`. The role is read from the database on every request. A non-admin gets `403 Forbidden`, and the attempt is logged as `forbidden_page`.
* **Tests:** `test_viewer_cannot_open_admin_page`.
* **Design choice:** An admin can see the audit log but cannot open a document without a grant, like any other user.

## 3. Removing access that should be gone (revoke)
* **Threat:** A user keeps reading a document after the owner removed their access.
* **What is built:** Revoke deletes the row in the `permissions` table, and `get_access()` reads that table on every request, so the next request is refused. Nothing about access is cached in the session.
* **Tests:** `test_revoke_works_on_the_very_next_request`.

## 4. No record of who did what (audit trail)
* **Threat:** Someone probes the system or leaks a file, and nobody can say who did it or when.
* **What is built:** An `audit_log` table. The app writes a row for uploads, downloads, grants, revokes, logins, failed logins, locked logins, refused pages and blocked forms, with the user, the document, the time and whether it was allowed. The admin page shows the latest 100 rows and counts of total and refused events.
* **Tests:** `test_refused_attempts_are_in_the_audit_log`.
* **Still open:** The log is append-only in the app, which means the app only adds rows. It is **not tamper-proof**. Anyone with direct access to the database file can edit or delete rows, and nothing in the app prevents that. The admin page has no search or paging yet.

## 5. Stealing or abusing the session
* **Threat:** Someone steals the session cookie, or reuses a session ID from before login.
* **What is built:** The cookie is `HttpOnly`, so JavaScript on a page cannot read it. It is `SameSite=Lax`. On the live site `COOKIE_SECURE=1` makes the browser send it only over HTTPS. The session is cleared and recreated at login. Passwords are stored as hashes (Werkzeug), never as plain text. The secret key comes from an environment variable on Render.
* **Still open:** There is no session expiry time, and no "log out everywhere".

## 6. Guessing passwords
* **Threat:** Someone tries many passwords for one username.
* **What is built:** After 5 failed logins for a username within 15 minutes, login for that username is refused. The failures and the lock are logged.
* **Tests:** `test_login_is_locked_after_five_failures`.
* **Trade-off:** The limit counts per username, so someone can lock another user out for 15 minutes by guessing wrong passwords on purpose. A better version would also count per IP address. That is not built yet.

## 7. Cross-site request forgery (CSRF)
* **Threat:** A malicious web page makes a logged-in user's browser send Share, Revoke or Log out requests without the user knowing.
* **What is built:** Every form contains a random token stored in the session. Every POST request without the right token is rejected with `400`, and the attempt is logged as `csrf_blocked`.
* **Tests:** `test_post_without_csrf_token_is_rejected`.
* **Still open:** The token is created once per session and not renewed after each request.

## 8. Malicious or oversized uploads
* **Threat:** A user uploads a harmful file, a huge file, or a file with a dangerous name.
* **What is built:** Only owners can upload. Only pdf, txt, png, jpg, jpeg, docx and xlsx files are accepted, up to 5 MB. The original name is cleaned with `secure_filename`, and the file is saved under a random name outside the public pages. Files are served only through the permission check, as a download.
* **Still open:** The check looks at the file extension only. A harmful file renamed to `.pdf` would be accepted. The file content is not scanned.

## 9. Injecting code through input
* **Threat:** SQL injection through the search box or forms, or script injection through a file name.
* **What is built:** All database queries use `?` placeholders, so typed text is never joined into the query. The page templates escape text automatically.

## 10. Other known limits
* `debug` is off on the live site, so the error debugger is not exposed.
* The demo accounts share one password that is set in an environment variable and is not stored in the repository.
* The free hosting plan resets uploaded files and the database when the server restarts.
* The `edit` access level can be granted, but no feature uses it yet.