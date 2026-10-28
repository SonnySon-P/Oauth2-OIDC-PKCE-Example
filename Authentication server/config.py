import os

class Config:
    DATABASE_NAME = "authentication_server.db"
    ADMIN_USERNAME = "sonnyson"
    ADMIN_EMAIL = "sonnyson@example.com"
    ADMIN_PASSWORD = "password-of-sonnyson"
    FLASK_SESSION_SECRET_KEY = os.getenv("FLASK_SESSION_SECRET", "dev-secret-key-change-me")
    KEY_ID = "sonnyson-rsa-key-1"
    AUTHENTICATION_URL = "http://127.0.0.1:6375"
    CLIENT_URL = "http://127.0.0.1:6789"

    CLIENTS = {
        "OAuth2.0_Demo_Website": {
            "client_secret": "cs_live_9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0",
            "redirect_uris": [
                "http://127.0.0.1:6789/callback",
            ],
            "scopes": {"openid", "profile", "email"}
        }
    }