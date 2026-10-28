# SonnySonID: End-to-End Authentication & Authorization Server Demonstration based on OAuth 2.0 + OIDC PKCE

I. Project Overview

SonnySonID is an end-to-end authentication and authorization server demonstration project that fully implements the standard  OIDC(OpenID Connect) Authorization Code Flow paired with PKCE (Proof Key for Code Exchange).

II. Development Environment
- Programming Language: Python
- Editor / IDE: Visual Studio Code

III. Dependencies
1. Authentication Server
- Flask: A lightweight and flexible WSGI web framework.
- PyJWT: A Python library used for generating, signing, decoding, and verifying JSON Web Tokens (JWT).
- cryptography: A robust cryptographic library.

2. Demo Website
- Flask: A lightweight and flexible WSGI web framework.
- PyJWT: A Python library used for generating, signing, decoding, and verifying JSON Web Tokens (JWT).
- httpx: A modern HTTP client used to securely send backend-to-backend requests.

IV. Operational Process
1. Authorization Initiation:
- The Demo Website generates security parameters, temporarily saves them, and redirects the browser to the Authorization Server.

2. Authentication & Authorization Code Issuance:
- The Authorization Server checks the user's authentication status. Upon successful authentication, it generates a short-lived, single-use authorization code, stores the relevant verification parameters in the database, and redirects the browser back to the Demo Website.

3. Back-Channel Token Exchange:
- After verifying that the state parameter is valid, the Demo Website sends a direct backend-to-backend POST request to the Authorization Server.
- The Authorization Server validates the client_secret, authorization code validity, and the code_verifier. Once verified, it immediately revokes the authorization code and signs a JWT ID Token.

4. Token Verification & Session Establishment:
- The Demo Website fetches the JWKS from the Authorization Server and uses PyJWT to strictly verify the digital signature, exp, iss, aud, and nonce.
- Upon successful verification, it clears the temporary security parameters, writes user data to the application session, completes the login process, and renders the success page.

V. Results
<br>
  <div align="center">
  	<img src="./screenshot_1.png" alt="Editor" width="500">
  </div>
<br>
<br>
<div align="center">
  	<img src="./screenshot_2.png" alt="Editor" width="500">
  </div>
<br>
