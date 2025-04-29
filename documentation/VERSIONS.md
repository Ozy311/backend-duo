# Component Versions

This file tracks the versions of key components used in the Reverse Proxy Auth Gateway project as of the last update.

## Core Application & Dependencies

Versions are primarily sourced from `flask_auth/requirements.txt` and the production environment.

*   **Python:** 3.10.12
*   **Flask:** (Latest available when `pip install Flask` was run, likely >= 2.0)
*   **click:** 8.1.8
*   **duo-universal:** (Latest available when `pip install duo-universal` was run)
*   **Flask-Login:** (Latest available when `pip install Flask-Login` was run)
*   **itsdangerous:** 2.2.0
*   **Jinja2:** 3.1.6
*   **python-dotenv:** (Latest available when `pip install python-dotenv` was run)
*   **Werkzeug:** 3.1.3
*   **ldap3:** (Latest available when `pip install ldap3` was run)
*   **PyJWT:** (Latest available when `pip install PyJWT` was run)
*   **gunicorn:** 23.0.0
*   **Flask-WTF:** (Latest available when `pip install Flask-WTF` was run)

*Note: For packages without explicit versions in `requirements.txt`, the version installed is the latest compatible version available at the time `pip install` or `pip wheel` was executed. It's recommended to pin specific versions in `requirements.txt` (e.g., `Flask==2.3.4`) for stricter reproducibility, especially before major updates or deployments.*

## Server Environment

*   **Operating System:** Ubuntu 22.04.5 LTS (Jammy Jellyfish)
*   **Nginx:** 1.18.0 (Ubuntu) 