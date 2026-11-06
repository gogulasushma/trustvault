# THREATS.md: Threat Modeling & Security Mitigation Analysis

This document details the critical security threats analyzed during the architecture of TrustVault and outlines the engineering mitigations implemented to defend the live application.

---

## 1. Unauthorized Data Access & Horizontal Privilege Escalation
*   **The Threat:** An authenticated user with a `viewer` or separate `owner` account attempts to guess or brute-force a document ID parameter via URL manipulation (IDOR - Insecure Direct Object References), gaining unauthorized access to files belonging to other owners.
*   **The Mitigation:** We strictly enforced server-side access validation boundaries inside the file download routing block (`/documents/<id>/download`). The application logic explicitly queries the access database to check if the current `session["user_id"]` matches the document's `owner_id` or possesses an active, unrevoked row entry inside the explicit access delegation parameters. If validation checks fail, the application intercepts the request and issues a standard `404 Not Found` response to hide file existence.

## 2. Broken Access Control on Administrative Privileges
*   **The Threat:** Regular accounts (`viewer` or `owner`) try to manually input the `/admin` URL path directly into their web browser address bar to view sensitive system diagnostic states or look at system-wide access records.
*   **The Mitigation:** We set up an explicit role verification guard at the top of the administrative endpoint function. The controller pulls the active user profile from the database session and checks if the `role` column evaluates explicitly to `admin`. If a non-admin account hits the route, the system blocks execution immediately with an explicit `403 Forbidden` response.

## 3. Failure to Monitor and Log Critical Failures (Insufficient Logging)
*   **The Threat:** An adversary attempts to brute-force a system file index or enumerate permissions, but engineers are unable to detect the malicious activity because the system doesn't maintain permanent records of access denials.
*   **The Mitigation:** We constructed an immutable `audit_log` transaction database table. Every single download request runs through a structured logging sequence where the file ID, the acting user ID, and the outcome boolean indicator (`allowed = 1` or `allowed = 0`) are written to the database. These records provide a searchable audit log for system administrators.

## 4. Insecure Session Hijacking & Credential Sniffing
*   **The Threat:** A malicious entity intercepts session cookie parameters over an unencrypted local link or via client-side cross-site scripting (XSS) vectors, stealing an active session state.
*   **The Mitigation:** We leveraged Flask's session hardening configuration flags along with production environment variables on Render. The application enforces cookie isolation using `COOKIE_SECURE = 1`, which dictates that cookies can only be transmitted across secure HTTPS tunnels. Additionally, `SESSION_COOKIE_HTTPONLY = True` is declared to completely block JavaScript engines from extracting session data.

## 5. Account lock-out abuse (known trade-off)
* **The Threat:** The login limit counts failed attempts per username, so someone can lock another user out for 15 minutes by guessing wrong passwords on purpose.
* **What we did:** We accept this to stop password guessing. A better version would also count attempts per IP address, which is not built yet.