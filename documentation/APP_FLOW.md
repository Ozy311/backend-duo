## Overview

This document describes the primary user interaction flows within the Reverse Proxy Auth Gateway.

## Key User Journeys

1.  **Unauthenticated Access Attempt:**
    * User navigates to the public-facing URL (e.g., `https://backend.your-company.com/`).
    * Nginx receives the request.
    * Nginx performs an `auth_request` sub-request to Flask's `/auth_check` endpoint.
    * Flask `/auth_check` finds no valid session, returns `401 Unauthorized`.
    * Nginx receives `401`, interprets it as "authentication required", and redirects the user's browser to `/login`.
    * User's browser loads the `/login` page served by Flask.

2.  **Successful Authentication (AD + Duo):**
    * User is on the `/login` page.
    * User enters correct Active Directory username and password, clicks "Login".
    * Browser POSTs credentials to Flask `/login`.
    * Flask `/login` validates credentials against Active Directory via LDAP -> **Success**.
    * Flask `/login` initiates Duo authentication using the `duo_universal_python` SDK.
    * Flask redirects the user's browser to the Duo Universal Prompt URL.
    * User interacts with the Duo prompt (e.g., approves push, enters code) -> **Success**.
    * Duo redirects the user's browser back to the Flask `/duo_callback` URL with a `code` and `state`.
    * Flask `/duo_callback` validates the `state` and exchanges the `code` with Duo's API via the SDK -> **Success**.
    * Flask establishes a secure user session (e.g., sets a signed cookie via Flask-Login).
    * Flask redirects the user's browser back to the originally requested URL or the root (`/`).
    * Browser requests `/`.
    * Nginx receives the request, performs `auth_request` to Flask `/auth_check`.
    * Flask `/auth_check` finds a valid session, returns `200 OK`.
    * Nginx receives `200 OK`, proxies the original request for `/` to the Tomcat backend (`http://localhost:8080`).
    * Tomcat responds, Nginx relays the response to the user. User sees the application.

3.  **Failed Active Directory Authentication:**
    * User is on the `/login` page.
    * User enters incorrect username or password, clicks "Login".
    * Browser POSTs credentials to Flask `/login`.
    * Flask `/login` validates credentials against Active Directory via LDAP -> **Failure**.
    * Flask re-renders the `login.html` template, passing an error message context (e.g., "Invalid username or password").
    * User sees the login page again with the error message.

4.  **Failed/Denied Duo Authentication:**
    * User has successfully authenticated with AD and is redirected to Duo.
    * User denies the Duo push notification, enters an incorrect passcode, or cancels the MFA attempt -> **Failure**.
    * Duo redirects the user's browser back to the Flask `/duo_callback` URL (potentially with error indicators).
    * Flask `/duo_callback` attempts to validate with Duo via the SDK -> **Failure** (or indication of denial).
    * Flask redirects the user back to the `/login` page, possibly with an error message (e.g., "Multi-factor authentication failed").

5.  **Authenticated Access (Subsequent Request):**
    * User has previously logged in successfully and has a valid session cookie.
    * User navigates to `https://backend.your-company.com/some_resource`.
    * Browser sends the request along with the Flask session cookie.
    * Nginx receives the request.
    * Nginx performs `auth_request` to Flask `/auth_check` (including the cookie).
    * Flask `/auth_check` validates the session cookie, finds the active session -> **Success**. Returns `200 OK`.
    * Nginx receives `200 OK`, proxies the request for `/some_resource` to Tomcat.
    * Tomcat responds, Nginx relays response to user.

6.  **Logout:**
    * User cannot access a logout mechanism but create a `/logout` that can be accessed in case a logout is needed for testing.