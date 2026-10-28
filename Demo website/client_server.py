from config import Config
from flask import Flask, request, session, redirect, abort
from urllib.parse import urlencode

import base64
import hashlib
import httpx
import jwt
import secrets

app = Flask(__name__)
app.secret_key = Config.FLASK_SESSION_SECRET_KEY

CLIENT_ID = Config.CLIENT_ID
CLIENT_SECRET = Config.CLIENT_SECRET
REDIRECT_URI = Config.CLIENT_URL + "/callback"
AUTHENTICATION_URL = Config.AUTHENTICATION_URL
DISCOVERY_URL = AUTHENTICATION_URL + "/.well-known/openid-configuration"
JWKS_URL = AUTHENTICATION_URL + "/.well-known/jwks.json"

def page(body: str) -> str:
    return f"""
        <!DOCTYPE html>
        <html lang="zh-TW">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OAuth 2.0 Demo Website</title>
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
                    background-color: #b89778;
                    color: #ffffff;
                    font-family: Georgia, "Times New Roman", serif;
                    text-align: center;
                }}

                h1, h2 {{
                    margin-bottom: 15px;
                }}

                p {{
                    margin: 10px 0;
                }}

                button {{
                    background-color: #ffffff;
                    color: #b89778;
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
                    background-color: #f0f0f0;
                }}
            </style>
        </head>
        <body>
            <h1>OAuth 2.0 Demo Website</h1>
            {body}
        </body>
        </html>
        """

@app.get("/")
def home():
    user = session.get("user")

    if not user:
        return page(
            """
            <p>You are not logged in.</p>
            <a href="/login">
                <button>Log in with SonnySonID</button>
            </a>
            """
        )

    username = user.get("preferred_username", "")

    return page(
        f"""
        <h2>Login successful</h2>
        <p>User：{username}</p>
        <form action="/logout" method="post">
            <button type="submit">Sign out</button>
        </form>
        """
    )

@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)

    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    session["pkce_verifier"] = verifier

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
        "code_challenge_method": "S256"
    }

    return redirect(AUTHENTICATION_URL + "/authorize?" + urlencode(params), code = 302)

@app.get("/callback")
def callback():
    error = request.args.get("error", "")
    code = request.args.get("code", "")
    state = request.args.get("state", "")

    if error:
        abort(400, description = "Authorization server denied authorization")

    oauth_state = session.pop("oauth_state", None)
    oauth_nonce = session.pop("oauth_nonce", None)
    pkce_verifier = session.pop("pkce_verifier", None)

    if not oauth_state or not secrets.compare_digest(state, oauth_state) or not oauth_nonce or not pkce_verifier or not code:
        abort(400, description = "Invalid state or OAuth callback data")

    with httpx.Client(timeout = 10.0) as client:
        discovery_response = client.get(DISCOVERY_URL)
        discovery_response.raise_for_status()
        metadata = discovery_response.json()

        if metadata.get("issuer") != AUTHENTICATION_URL:
            abort(502, description = "Authentication server issuer mismatch")

        token_endpoint = metadata["token_endpoint"]

        if not token_endpoint.startswith(AUTHENTICATION_URL + "/"):
            abort(502, description = "Invalid token endpoint")

        token_response = client.post(
            token_endpoint,
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": pkce_verifier,
            },
        )

        if token_response.status_code != 200:
            abort(401, description = "Authorization code exchange failed")

        tokens = token_response.json()

    id_token = tokens.get("id_token")

    if not id_token:
        abort(401, description = "Missing ID token")

    jwks_client = jwt.PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms = ["RS256"],
            issuer = AUTHENTICATION_URL,
            audience = CLIENT_ID,
            leeway = 30,
            options = {
                "require": [
                    "iss", "sub", "aud", "exp", "iat", "nonce"
                ],
            },
        )

    except jwt.PyJWTError as e:
        abort(401, description = "ID token verification failed")

    if not secrets.compare_digest(str(claims.get("nonce", "")), oauth_nonce):
        abort(401, description = "Nonce mismatch")

    session.clear()
    session["user"] = {
        "sub": claims["sub"],
        "preferred_username": claims.get("preferred_username", ""),
    }

    return redirect("/", code = 303)

@app.post("/logout")
def logout():
    session.clear()
    return redirect("/", code = 303)

if __name__ == "__main__":
    app.run(host = "0.0.0.0", port = 6789, debug = True)