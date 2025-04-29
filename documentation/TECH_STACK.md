## Overview

This document outlines the technologies used in the Reverse Proxy Auth Gateway project.

## Technology Stack

* **Operating System (Target):**
    * Ubuntu Linux (Latest LTS recommended)

* **Reverse Proxy:**
    * **Nginx:** (Preferred) High-performance web server and reverse proxy. Will handle incoming requests, SSL termination, and conditional proxying based on authentication status.

* **Authentication Layer (Backend):**
    * **Language:** Python (3.9+)
    * **Framework:** Flask - Microframework for building the authentication web application.
    * **WSGI Server:** Gunicorn or uWSGI (For running Flask in production behind Nginx).

* **Authentication Libraries:**
    * **Active Directory:** `ldap3` (Recommended) or `python-ldap` - For connecting to and authenticating against Active Directory via LDAP/LDAPS.
    * **Duo MFA:** `duo_universal_python` - Official Duo Security SDK for integrating with the Universal Prompt via OIDC/API calls.
    * **Environment Variables:** `python-dotenv` - For managing configuration secrets securely via `.env` files.
    * **Forms & CSRF:** `Flask-WTF` (includes `WTForms`) - For handling web forms and CSRF protection.

* **Session Management:**
    * `Flask-Login` or `Flask-Session` - To handle user sessions securely using server-signed cookies.

* **Backend Application Server:**
    * **Apache Tomcat:** Hosts the legacy Java application. Expected to be running and listening only on `localhost:8080`.

* **Authentication Frontend (UI):**
    * **HTML:** HTML5 for the login form structure.
    * **CSS:** CSS3 for basic styling (minimalist approach).
    * **JavaScript:** Minimal, if needed, for basic frontend interactions on the login page. No heavy frameworks required.

* **Development & Deployment:**
    * **Version Control:** Git
    * **Environment Management:** Python Virtual Environments (`venv`)
    * **Dependency Management:** `pip` with `requirements.txt`
