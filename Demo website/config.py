import os

class Config:
    FLASK_SESSION_SECRET_KEY = os.getenv("FLASK_SESSION_SECRET", "dev-secret-key-change-me")
    CLIENT_ID = "OAuth2.0_Demo_Website"
    CLIENT_URL = os.getenv("CLIENT_URL", "http://127.0.0.1:6789")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET","cs_live_9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0")
    AUTHENTICATION_URL = os.getenv("AUTHENTICATION_URL", "http://127.0.0.1:6375")
