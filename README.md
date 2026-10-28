# SonnySonID: End-to-End Authentication & Authorization Server Demonstration based on OAuth 2.0 + OIDC PKCE

I. Project Overview

SonnySonID is an end-to-end authentication and authorization server demonstration project that fully implements the standard  OIDC(OpenID Connect) Authorization Code Flow paired with PKCE (Proof Key for Code Exchange).

II. Development Environment
- Programming Language: Python
- Editor / IDE: Visual Studio Code

III. Dependencies
1. Authentication Server
Flask: A lightweight and flexible WSGI web framework.
PyJWT: A Python library used for generating, signing, decoding, and verifying JSON Web Tokens (JWT).
cryptography: A robust cryptographic library.

3. Demo Website
Flask: A lightweight and flexible WSGI web framework.
PyJWT: A Python library used for generating, signing, decoding, and verifying JSON Web Tokens (JWT).
httpx: A modern HTTP client used to securely send backend-to-backend requests.

IV. Operating Steps
1. Authorization Initiation

The Demo Website generates security parameters, temporarily saves them, and redirects the browser to the Authorization Server.

2. Authentication & Authorization Code Issuance
3. 
The Authorization Server checks the user's authentication status. Upon successful authentication, it generates a short-lived, single-use authorization code, stores the relevant verification parameters in the database, and redirects the browser back to the Demo Website.


