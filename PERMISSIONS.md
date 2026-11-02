# TrustVault Permission Model

## Roles
- **Admin**: manages users, sees the audit log and all activity. Cannot open a document's contents unless granted access like anyone else.
- **Owner**: uploads documents, grants and revokes access to named users, deletes own documents.
- **Viewer**: sees only the documents that were granted to them.

## Document permissions
- **read**: view and download the document.
- **edit**: read, plus upload a new version and change details.
- Only the owner can grant or revoke permissions.

## Rules
1. Default is deny: if there is no grant, access is refused.
2. The server checks the database on every request. Hiding a button is not security.
3. Every attempt is written to the audit log, allowed or refused.
4. Revoking deletes the grant, so it stops working on the very next request.
5. Files are stored outside any public folder and are served only after the permission check.