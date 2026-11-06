# TrustVault routes

The app returns HTML pages. A user who is not logged in is redirected to `/login`.

| Method | Path | Who can use it | What it does |
|---|---|---|---|
| GET | `/` | anyone | Redirects to the dashboard or the login page |
| GET, POST | `/register` | anyone | Create an account (always starts as `viewer`) |
| GET, POST | `/login` | anyone | Log in. Failed attempts go to the audit log |
| POST | `/logout` | logged in | Log out |
| GET | `/dashboard` | logged in | Shows the user's name and role |
| GET | `/admin` | admin only | Audit log and counts. Others get 403 |
| GET, POST | `/upload` | owner only | Upload a file with a category. Others get 403 |
| GET | `/documents` | logged in | List documents the user owns or was granted |
| GET | `/documents/<id>/download` | owner or granted user | Download a document. Anyone else gets 404 |
| GET, POST | `/documents/<id>/share` | owner of that document | Grant or revoke read/edit access. Anyone else gets 404 |

## Search on `/documents`

Optional query parameters: `q` (name contains), `owner`, `category`, `date_from`, `date_to` (YYYY-MM-DD).
Search only looks at documents the user can already access.

## Access rules

- Every document route calls `get_access()`, which reads the database on each request.
- A refused request is written to the audit log with `allowed = 0`.
- A document the user cannot access returns 404, the same as a document that does not exist.
- Upload accepts pdf, txt, png, jpg, jpeg, docx and xlsx, up to 5 MB.