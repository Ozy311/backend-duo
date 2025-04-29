## Overview

This document describes the backend architecture and data flow involving Nginx, the Flask Authentication application, and the backend Tomcat application.

## Architecture

The system employs a reverse proxy pattern where Nginx acts as the gatekeeper. All user traffic hits Nginx first. Nginx routes requests to the Flask application for login and authentication checks. Only upon successful authentication confirmation from Flask does Nginx proxy the request to the internal Tomcat server.

## Component Roles

1.  **Nginx:**
    * Listens on 80 ports.
    * Serves static assets for the login page (can be delegated to Flask during development).
    * Redirects unauthenticated users trying to access protected resources (`/`) to the Flask login endpoint (`/login`).
    * Routes `/login`, `/logout`, and `/duo_callback` paths directly to the Flask application.
    * **Crucially:** Before proxying requests to Tomcat (`/`), it uses the `auth_request` module to make a sub-request to a dedicated Flask endpoint (e.g., `/auth_check`).
    * If `/auth_check` returns `200 OK`, Nginx proceeds to proxy the original request to `http://localhost:8080`.
    * If `/auth_check` returns `401 Unauthorized` (or similar), Nginx redirects the user to `/login`.
    * Passes necessary headers (like `X-Forwarded-For`, `X-Forwarded-Proto`) to both Flask and Tomcat.

2.  **Flask Authentication App (`flask_auth`):**
    * Runs as a WSGI application (e.g., via Gunicorn) typically listening on a local port (e.g., `localhost:5000`).
    * **`/login` (GET):** Renders the `login.html` template.
    * **`/login` (POST):**
        * Receives username/password.
        * Attempts authentication against Active Directory using `ldap3`.
        * If AD auth fails, re-renders `login.html` with an error.
        * If AD auth succeeds, initiates Duo flow using `duo_universal_python` SDK and redirects user browser to Duo.
    * **`/duo_callback` (GET):**
        * Receives callback from Duo after MFA attempt.
        * Validates the `state` parameter.
        * Uses SDK to exchange the received `code` for a 2FA result.
        * If Duo validation fails, redirects to `/login` with an error.
        * If Duo validation succeeds, creates a secure user session (e.g., using Flask-Login `login_user`) and redirects the user to the originally requested URL or the root (`/`).
    * **`/auth_check` (GET):** (For Nginx `auth_request`)
        * Checks if a valid user session exists (e.g., via Flask-Login's `current_user.is_authenticated`).
        * Returns HTTP `200 OK` if authenticated.
        * Returns HTTP `401 Unauthorized` if not authenticated.
    * **`/logout` (GET/POST):**
        * Clears the user session (e.g., Flask-Login `logout_user`).
        * Redirects to `/login`.
    * Manages secure storage and retrieval of session data (typically server-signed cookies).
    * Loads configuration (AD details, Duo keys, Flask secret, cookie session length) from environment variables / `.env` file.

3.  **Tomcat Application:**
    * Hosts the legacy Java application.
    * Listens *only* on `localhost:8080` (or another internal port). It should not be directly accessible from outside the server.
    * Receives authenticated user requests proxied by Nginx.
    * Assumed to be unaware of the external AD/Duo authentication; it sees requests as coming from Nginx.

## Data Flow (Simplified Login)

1.  User requests `/`.
2.  Nginx receives request. `auth_request` to Flask `/auth_check`.
3.  Flask `/auth_check` finds no session, returns `401`.
4.  Nginx sees `401`, redirects User to `/login`.
5.  User sees login form, submits username/password.
6.  Flask `/login` (POST) receives credentials.
7.  Flask validates credentials against Active Directory -> **Success**.
8.  Flask generates Duo auth URL, redirects User browser to Duo.
9.  User completes Duo MFA -> **Success**.
10. Duo redirects User browser back to Flask `/duo_callback` with `code` and `state`.
11. Flask `/duo_callback` validates `state`, exchanges `code` with Duo -> **Success**.
12. Flask creates session (sets secure cookie), redirects User to `/`.
13. Nginx receives request for `/`. `auth_request` to Flask `/auth_check`.
14. Flask `/auth_check` finds valid session, returns `200 OK`.
15. Nginx sees `200 OK`, proxies the request for `/` to Tomcat `localhost:8080`.
16. Tomcat processes request and sends response back through Nginx to the User.
