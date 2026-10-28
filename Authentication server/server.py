from config import Config
from contextlib import contextmanager
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta
from flask import Flask, request, session, redirect, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlencode, urlparse
import base64
import hashlib
import html
import jwt
import os
import secrets
import sqlite3

app = Flask(__name__)
app.secret_key = Config.FLASK_SESSION_SECRET_KEY

DATABASE_NAME = Config.DATABASE_NAME
AUTHENTICATION_URL = Config.AUTHENTICATION_URL
CLIENTS = Config.CLIENTS

PRIVATE_KEY_FILE = "private_key.pem"

if os.path.exists(PRIVATE_KEY_FILE):
    with open(PRIVATE_KEY_FILE, "rb") as f:
        PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password = None)

else:
    PRIVATE_KEY = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(PRIVATE_KEY.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))

PUBLIC_KEY = PRIVATE_KEY.public_key()
KEY_ID = Config.KEY_ID

@contextmanager
def get_db():
    db = sqlite3.connect(DATABASE_NAME, timeout = 30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")

    try:
        yield db
        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                username TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                nonce TEXT,
                code_challenge TEXT,
                expires_at TEXT NOT NULL
            )
            """
        )

        admin = db.execute("SELECT id FROM users WHERE username = ?", (Config.ADMIN_USERNAME,)).fetchone()

        if admin is None:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (Config.ADMIN_USERNAME, generate_password_hash(Config.ADMIN_PASSWORD)))

def page(body: str) -> str:
    return f"""
        <!DOCTYPE html>
        <html lang="zh-TW">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SonnySonID Authentication Server</title>
            <style>
                html, body {{
                    height: 100%;
                    margin: 0;
                }}

                body {{
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    background-color: #2c3e50;
                    color: #ffffff;
                    font-family: Georgia, "Times New Roman", serif;
                    text-align: center;
                }}

                h1, h2 {{
                    margin-bottom: 15px;
                }}

                label {{ 
                    display: block; margin: 10px 0;
                }}

                input {{ 
                    padding: 8px; 
                    font-size: 16px; 
                    border-radius: 4px; 
                    border: 1px solid #ccc; 
                    margin-left: 5px; 
                }}

                p {{
                    margin: 10px 0;
                }}

                button {{ 
                    background-color: #3498db; 
                    color: white; 
                    border: none; 
                    padding: 10px 20px; 
                    font-family: Georgia, "Times New Roman", serif;
                    font-size: 16px; 
                    cursor: pointer;
                    border-radius: 4px; 
                    margin-top: 10px; 
                    font-weight: bold; 
                }}

                button:hover {{ 
                    background-color: #2980b9; 
                }}

                a {{ 
                    color: #3498db; 
                    text-decoration: none; 
                }}

                a:hover {{ 
                    text-decoration: underline; 
                }}
            </style>
        </head>
        <body>
            {body}
        </body>
        </html>
        """

def is_safe_url(target):
    refer_url = urlparse(target)
    return not refer_url.netloc and not refer_url.scheme and target.startswith("/")

def int_to_base64(n):
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode("utf-8")

@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": AUTHENTICATION_URL,
        "authorization_endpoint": AUTHENTICATION_URL + "/authorize",
        "token_endpoint": AUTHENTICATION_URL + "/token",
        "jwks_uri": AUTHENTICATION_URL + "/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })

@app.get("/.well-known/jwks.json")
def jwks():
    public_numbers = PUBLIC_KEY.public_numbers()

    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KEY_ID,
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e)
        }]
    })

@app.get("/authorize")
def authorize():
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid")
    state = request.args.get("state", "")
    nonce = request.args.get("nonce", "")
    code_challenge = request.args.get("code_challenge", "")
    code_challenge_method = request.args.get("code_challenge_method", "")

    client = CLIENTS.get(client_id)

    if not client or redirect_uri not in client["redirect_uris"]:
        abort(400, description = "Invalid client_id or redirect_uri")

    if response_type != "code":
        abort(400, description = "Only response_type = code is supported")

    scopes = set(scope.split())

    if "openid" not in scopes or not scopes.issubset(client["scopes"]):
        abort(400, description = "Invalid scope")

    if not state or len(state) > 512:
        abort(400, description = "Missing or invalid state")

    if not nonce or len(nonce) > 512:
        abort(400, description = "Missing or invalid nonce")

    if code_challenge_method != "S256":
        abort(400, description = "PKCE S256 is required")

    if len(code_challenge) != 43:
        abort(400, description = "Invalid PKCE challenge")

    user_id = session.get("user_id")

    if not user_id:
        query_string = request.query_string.decode("utf-8")
        next_url = "/authorize" + (f"?{query_string}" if query_string else "")
        return redirect(f"/login?{urlencode({'next': next_url})}", code = 303)

    code = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds = 120)).isoformat()

    with get_db() as db:
        db.execute(
            """
            INSERT INTO authorization_codes (code, client_id, username, redirect_uri, nonce, code_challenge, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (code, client_id, user_id, redirect_uri, nonce, code_challenge, expires_at)
        )

    return redirect(
        redirect_uri + "?" + urlencode({
            "code": code,
            "state": state,
        }),
        code = 303,
    )

@app.get("/login")
def login_page():
    next_url = request.args.get("next", "/")
    if next_url != "/" and not is_safe_url(next_url):
        abort(400, description = "Invalid login redirect")

    return page(
        f"""
        <h1>Login to SonnySonID</h1>
        <form method="post" action="/login">
            <input type="hidden" name="next" value="{html.escape(next_url, quote = True)}">
            <label>Username: <input name="username" autocomplete="username" required></label><br>
            <label>Password: <input type="password" name="password" autocomplete="current-password" required></label><br>
            <button type="submit">Log In</button>
        </form>
        <p style="margin-top: 20px;">Don't have an account? <a href="/register">Register here</a></p>
        """
    )

@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next", "/")

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return page(
            f"""
            <h2>Login Failed</h2>
            <p>Invalid username or password</p>
            <a href="/login?next={html.escape(next_url, quote=True)}">
                <button>Try Again</button>
            </a>
            """
        )

    session["user_id"] = user["username"]

    if not is_safe_url(next_url):
        next_url = "/"

    return redirect(next_url, code = 303)

@app.get("/register")
def register_page():
    return page(
        """
        <h1>Register New Account</h1>
        <form method="post" action="/register">
            <label>Username: <input name="username" autocomplete="username" required></label><br>
            <label>Password: <input type="password" name="password" autocomplete="new-password" required></label><br>
            <button type="submit">Sign Up</button>
        </form>
        <p style="margin-top: 20px;">Already have an account? <a href="/login">Log In</a></p>
        """
    )

@app.post("/register")
def register_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return page(
            """
            <h2>Registration Failed</h2>
            <p>All fields are required.</p>
            <a href="/register">
                <button>Try Again</button>
            </a>
            """
        )

    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, generate_password_hash(password)))

    except sqlite3.IntegrityError:
        return page(
            """
            <h2>Registration Failed</h2>
            <p>Username already exists.</p>
            <a href="/register">
                <button>Try Again</button>
            </a>
            """
        )

    return page(
        """
        <h2>Registration Successful</h2>
        <p>Your account has been created successfully.</p>
        <a href="/login">
            <button>Go to Login</button>
        </a>
        """
    )

@app.post("/token")
def token_endpoint():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code" or not code:
        return jsonify({"error": "invalid_request"}), 400

    client = CLIENTS.get(client_id)
    
    if not client or client["client_secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    with get_db() as db:
        authorization_data = db.execute("SELECT * FROM authorization_codes WHERE code = ?", (code,)).fetchone()
        db.execute("DELETE FROM authorization_codes WHERE code = ?", (code,))

    if not authorization_data:
        return jsonify({"error": "invalid_grant"}), 400

    expires_at = datetime.fromisoformat(authorization_data["expires_at"])

    if datetime.now(timezone.utc) > expires_at:
        return jsonify({"error": "invalid_grant", "error_description": "Authorization code expired"}), 400

    if authorization_data["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant", "error_description": "Redirect URI mismatch"}), 400

    if authorization_data["code_challenge"]:
        expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()

        if expected_challenge != authorization_data["code_challenge"]:
            return jsonify({"error": "invalid_grant", "error_description": "PKCE verification failed"}), 400

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (authorization_data["username"],)).fetchone()

    if not user:
        return jsonify({"error": "invalid_grant", "error_description": "User not found"}), 400

    now = datetime.now(timezone.utc)
    payload = {
        "iss": AUTHENTICATION_URL,
        "sub": str(user["id"]),
        "aud": client_id,
        "exp": now + timedelta(minutes = 10),
        "iat": now,
        "nonce": authorization_data["nonce"],
        "preferred_username": user["username"]
    }

    id_token = jwt.encode(payload, PRIVATE_KEY, algorithm = "RS256", headers = {"kid": KEY_ID})

    return jsonify({
        "access_token": secrets.token_urlsafe(32),
        "token_type": "Bearer",
        "id_token": id_token
    })

@app.post("/logout")
def logout():
    session.clear()
    return redirect("/", code = 303)

if __name__ == "__main__":
    init_db()
    app.run(host = "0.0.0.0", port = 6375, debug = True)