# JWKS Server (Project 2: SQLite-backed)

A small Flask server that publishes RSA public keys as a JWKS and issues signed
JWTs. Project 2 extends Project 1 by storing the private keys in a SQLite
database so they persist across server restarts.

## How it works

- On startup the server opens (or creates) `totally_not_my_privateKeys.db` with
  this table:

  ```sql
  CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
  )
  ```
- If the database has no valid key, it generates one that expires in 1 hour.
  If it has no expired key, it generates one that expired 1 hour ago.
- Keys are serialized to PKCS1 PEM before being saved, and deserialized when
  read, since SQLite has no RSA key type.
- `GET /.well-known/jwks.json` reads all **unexpired** keys from the database
  and returns their public halves.
- `POST /auth` reads an unexpired key from the database and returns a JWT
  (RS256) signed with it, with the `kid` in the header. With `?expired`, it
  reads an expired key instead and sets `exp` in the past. User authentication
  is mocked: HTTP Basic auth and a JSON body are both accepted.
- Every SQL query uses `?` parameters, so values are never inserted into the
  SQL text. This prevents SQL injection.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask app and the two endpoints |
| `keys.py` | Key generation, PEM serialization, SQLite storage and queries |
| `tests/` | pytest test suite |

## Setup and run

```
pip install -r requirements.txt
python app.py
```

The server listens on http://localhost:8080.

## Tests and lint

```
python -m pytest --cov=. --cov-report=term-missing
python -m flake8 .
```

## AI usage

AI (Claude) was used on this project. See [AI_USAGE.md](AI_USAGE.md) for the
acknowledgement and the list of prompts.

## Screenshots

- `screenshots/gradebot.png` - the course Gradebot client running against the server
- `screenshots/coverage.png` - pytest coverage report
