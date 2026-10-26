"""Flask app for the JWKS server.

Endpoints:
    GET  /.well-known/jwks.json  -> public keys that haven't expired
    POST /auth                   -> a signed JWT (add ?expired for an expired one)

Keys are read from the SQLite database on every request (see keys.py).
"""

import sqlite3
import time

import jwt
from flask import Flask, jsonify, request

from keys import KeyStore, generate_private_key, VALID_KEY_LIFETIME

TOKEN_LIFETIME = 5 * 60  # normal tokens last 5 minutes


def create_app(key_store=None):
    """Build the Flask app. A key store can be passed in for testing."""
    app = Flask(__name__)
    store = key_store or KeyStore()

    @app.errorhandler(sqlite3.Error)
    def database_error(_err):
        """Return a generic 500 so database details never leak to the client."""
        return jsonify({"error": "internal server error"}), 500

    @app.route("/.well-known/jwks.json", methods=["GET"])
    def jwks():
        """Return the public JWKS built from every unexpired key in the DB."""
        return jsonify(store.jwks())

    @app.route("/auth", methods=["POST"])
    def auth():
        """Return a JWT signed with a key read from the database.

        A valid key is used by default; ?expired switches to an expired key
        and an exp claim in the past.
        """
        # User auth is mocked: Basic auth or a JSON body are both accepted
        # without checking. The mere presence of ?expired counts.
        expired = "expired" in request.args
        key = store.get_key(expired=expired)
        if key is None:
            # The valid key ran out while the server was up, so make a new one.
            store.add_key(generate_private_key(), int(time.time()) + VALID_KEY_LIFETIME)
            key = store.get_key(expired=False)

        if expired:
            exp = key.expires_at  # already in the past
        else:
            exp = int(time.time()) + TOKEN_LIFETIME

        payload = {
            "sub": "fakeuser",
            "iat": int(time.time()),
            "exp": exp,
        }
        # kid goes in the header so clients know which key to verify with.
        token = jwt.encode(
            payload,
            key.private_pem(),
            algorithm="RS256",
            headers={"kid": str(key.kid)},
        )
        # Send the raw JWT as the body.
        return token, 200, {"Content-Type": "text/plain; charset=utf-8"}

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
