# SonnySonID: End-to-End Authentication & Authorization Server Demonstration based on OAuth 2.0 + OIDC PKCE

I. Project Overview

SonnySonID is an end-to-end authentication and authorization server demonstration project that fully implements the standard  OIDC(OpenID Connect) Authorization Code Flow paired with PKCE (Proof Key for Code Exchange).

II. Development Environment
- Programming Language: Python
- Editor / IDE: Visual Studio Code

III. Dependencies
- Cryptography: It is a cryptographic library that provides many ready-to-use and secure cryptographic algorithms.

IV. Operating Steps

1. Generate an Ed25519 public-private key pair in OpenSSH format.
2. Deploy server.py and client.py on two separate computers, and modify the IP address and port in the code according to the network environment.
3. Configure the Ed25519 public key on the Server and the corresponding private key on the Client.
4. Run the programs on their respective computers.
