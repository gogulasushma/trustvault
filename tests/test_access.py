import io
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

import app as trustvault

SCHEMA = Path(__file__).parent.parent / "schema.sql"
PASSWORD = "test-password-123"
CONTENT = b"secret content"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A fresh empty database and upload folder for every test."""
    db_path = tmp_path / "test.db"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(trustvault, "DATABASE", str(db_path))
    monkeypatch.setattr(trustvault, "UPLOAD_FOLDER", upload_dir)

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    users = [("admin1", "admin"), ("owner1", "owner"), ("owner2", "owner"),
             ("viewer1", "viewer"), ("viewer2", "viewer")]
    for username, role in users:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(PASSWORD), role),
        )
    conn.commit()
    conn.close()

    trustvault.app.config["TESTING"] = True
    with trustvault.app.test_client() as test_client:
        yield test_client


def login(client, username):
    return client.post("/login", data={"username": username, "password": PASSWORD})


def logout(client):
    return client.post("/logout")


def owner_uploads_document(client, username="owner1"):
    """Owner uploads one file. In a fresh database it gets id 1."""
    login(client, username)
    client.post(
        "/upload",
        data={"file": (io.BytesIO(CONTENT), "secret.txt"), "category": "Other"},
        content_type="multipart/form-data",
    )
    logout(client)
    return 1


def owner_changes_access(client, action, target, username="owner1", doc_id=1):
    login(client, username)
    response = client.post(
        f"/documents/{doc_id}/share",
        data={"action": action, "username": target, "level": "read"},
    )
    logout(client)
    return response


def test_not_logged_in_is_sent_to_login(client):
    owner_uploads_document(client)
    response = client.get("/documents/1/download")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_owner_can_download_own_document(client):
    owner_uploads_document(client)
    login(client, "owner1")
    response = client.get("/documents/1/download")
    assert response.status_code == 200
    assert response.data == CONTENT


def test_viewer_without_grant_is_refused(client):
    owner_uploads_document(client)
    login(client, "viewer1")
    assert client.get("/documents/1/download").status_code == 404


def test_other_owner_cannot_reach_document(client):
    owner_uploads_document(client)
    login(client, "owner2")
    assert client.get("/documents/1/download").status_code == 404
    assert client.get("/documents/1/share").status_code == 404


def test_admin_cannot_read_document_without_grant(client):
    owner_uploads_document(client)
    login(client, "admin1")
    assert client.get("/documents/1/download").status_code == 404


def test_grant_gives_read_access(client):
    owner_uploads_document(client)
    owner_changes_access(client, "grant", "viewer1")
    login(client, "viewer1")
    response = client.get("/documents/1/download")
    assert response.status_code == 200
    assert response.data == CONTENT


def test_grant_to_one_user_does_not_help_another(client):
    owner_uploads_document(client)
    owner_changes_access(client, "grant", "viewer1")
    login(client, "viewer2")
    assert client.get("/documents/1/download").status_code == 404


def test_revoke_works_on_the_very_next_request(client):
    owner_uploads_document(client)
    owner_changes_access(client, "grant", "viewer1")
    login(client, "viewer1")
    assert client.get("/documents/1/download").status_code == 200
    logout(client)

    owner_changes_access(client, "revoke", "viewer1")
    login(client, "viewer1")
    assert client.get("/documents/1/download").status_code == 404


def test_viewer_cannot_share_a_document_with_read_access(client):
    owner_uploads_document(client)
    owner_changes_access(client, "grant", "viewer1")
    login(client, "viewer1")
    assert client.get("/documents/1/share").status_code == 404
    response = client.post(
        "/documents/1/share",
        data={"action": "grant", "username": "viewer2", "level": "read"},
    )
    assert response.status_code == 404
    logout(client)
    login(client, "viewer2")
    assert client.get("/documents/1/download").status_code == 404


def test_viewer_cannot_upload(client):
    login(client, "viewer1")
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"x"), "x.txt"), "category": "Other"},
        content_type="multipart/form-data",
    )
    assert response.status_code == 403


def test_viewer_cannot_open_admin_page(client):
    login(client, "viewer1")
    assert client.get("/admin").status_code == 403


def test_admin_can_open_admin_page(client):
    login(client, "admin1")
    assert client.get("/admin").status_code == 200


def test_search_never_shows_documents_without_access(client):
    owner_uploads_document(client)
    login(client, "viewer1")
    response = client.get("/documents?q=secret")
    assert response.status_code == 200
    assert b"secret.txt" not in response.data


def test_refused_attempts_are_in_the_audit_log(client):
    owner_uploads_document(client)
    login(client, "viewer1")
    client.get("/documents/1/download")
    conn = sqlite3.connect(trustvault.DATABASE)
    rows = conn.execute(
        "SELECT user_id, action, allowed FROM audit_log "
        "WHERE action = 'download' AND allowed = 0"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    

def test_login_is_locked_after_five_failures(client):
    for _ in range(5):
        client.post("/login", data={"username": "viewer1", "password": "wrong-password"})
    response = client.post("/login", data={"username": "viewer1", "password": PASSWORD})
    assert b"Too many failed attempts" in response.data
    assert client.get("/dashboard").status_code == 302