import sqlite3
import time
from contextlib import closing

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from app import create_app
from keys import KeyStore, DB_FILE


@pytest.fixture
def store(tmp_path):
    return KeyStore(tmp_path / "test.db")


@pytest.fixture
def client(store):
    return create_app(store).test_client()


def public_key_for(client, kid):
    """Look up a kid in the JWKS and turn it into a key PyJWT can verify with."""
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    jwk = next(k for k in keys if k["kid"] == kid)
    return RSAAlgorithm.from_jwk(jwk)


def test_jwks_returns_valid_key(client, store):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    kids = [k["kid"] for k in resp.get_json()["keys"]]
    assert str(store.get_key(expired=False).kid) in kids


def test_jwks_does_not_return_expired_key(client, store):
    kids = [k["kid"] for k in client.get("/.well-known/jwks.json").get_json()["keys"]]
    assert str(store.get_key(expired=True).kid) not in kids


def test_auth_returns_verifiable_jwt(client, store):
    token = client.post("/auth").get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == str(store.get_key(expired=False).kid)
    assert header["alg"] == "RS256"

    claims = jwt.decode(
        token, public_key_for(client, header["kid"]), algorithms=["RS256"]
    )
    assert claims["exp"] > time.time()


def test_auth_accepts_basic_auth_and_json(client):
    # The test client sends both of these; auth is mocked so both should work.
    assert client.post("/auth", auth=("userABC", "password123")).status_code == 200
    resp = client.post(
        "/auth", json={"username": "userABC", "password": "password123"}
    )
    assert resp.status_code == 200


def test_auth_expired_uses_expired_key(client, store):
    resp = client.post("/auth?expired")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)

    expired_key = store.get_key(expired=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == str(expired_key.kid)

    # Expired key isn't in the JWKS, so verify with it directly
    # and turn off the exp check to read the claims.
    public_key = expired_key.private_key.public_key()
    claims = jwt.decode(
        token, public_key, algorithms=["RS256"], options={"verify_exp": False}
    )
    assert claims["exp"] < time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])


def test_auth_makes_new_key_when_valid_key_is_gone(client, store):
    # Simulate the valid key expiring while the server is running.
    with closing(sqlite3.connect(store.db_path)) as conn, conn:
        conn.execute("UPDATE keys SET exp = ?", (int(time.time()) - 1,))
    assert store.get_key(expired=False) is None

    token = client.post("/auth").get_data(as_text=True)
    kid = jwt.get_unverified_header(token)["kid"]
    claims = jwt.decode(token, public_key_for(client, kid), algorithms=["RS256"])
    assert claims["exp"] > time.time()


def test_wrong_methods_are_rejected(client):
    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.get("/auth").status_code == 405
    assert client.put("/auth").status_code == 405
    assert client.delete("/.well-known/jwks.json").status_code == 405


def test_unknown_route_is_404(client):
    assert client.get("/nope").status_code == 404


def test_default_store_uses_db_file(tmp_path, monkeypatch):
    # With no store passed in, the app creates the DB file in the current folder.
    monkeypatch.chdir(tmp_path)
    resp = create_app().test_client().get("/.well-known/jwks.json")
    assert len(resp.get_json()["keys"]) == 1
    assert (tmp_path / DB_FILE).exists()


def test_database_error_returns_500(client, store):
    # If the DB can't be read, the client gets a generic error, not a traceback.
    store.db_path = store.db_path.parent / "missing_dir" / "test.db"
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 500
    assert resp.get_json() == {"error": "internal server error"}
