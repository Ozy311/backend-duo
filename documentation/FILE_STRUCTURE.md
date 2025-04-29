## Overview

This document proposes the standard directory and file organization for the Reverse Proxy Auth Gateway codebase.

## Proposed Structure

```
reverse-proxy-auth-gateway/
├── nginx/
│   └── nginx.conf
├── flask_auth/
│   ├── app.py
│   ├── auth.py
│   ├── models.py
│   ├── utils.py
│   ├── static/
│   │   └── css/
│   │       └── style.css
│   └── templates/
│       └── login.html
│   ├── .env.example
│   └── requirements.txt
├── .gitignore
├── .env
├── documentation/  # Renamed from 'docs' for clarity
│   ├── PROJECT_REQUIREMENTS.md
│   ├── TECH_STACK.md
│   ├── BACKEND_STRUCTURE.md
│   ├── FRONTEND_GUIDELINES.md
│   ├── FILE_STRUCTURE.md
│   ├── APP_FLOW.md
│   ├── PROGRESS.md
│   ├── UPDATES.md
│   ├── VERSIONS.md
│   └── BUGS.md
└── README.md
```

## Key Directory Explanations

*   **`nginx/`**: Contains Nginx configuration files. `nginx.conf` will define the server blocks, location directives, SSL settings, and proxy rules.
*   **`flask_auth/`**: Root directory for the Python Flask application handling authentication.
    *   `app.py`: Initializes the Flask app, defines routes (`/login`, `/logout`, `/duo_callback`, `/auth_check`).
    *   `auth.py`: Contains functions for interacting with Active Directory (LDAP) and the Duo Universal Prompt SDK. Keeps authentication logic separate from route definitions.
    *   `models.py`: Defines the User class if using Flask-Login for session management.
    *   `static/`: Standard Flask directory for static files (CSS, JS). Contains `css/style.css`. Note: `logo.png` should be placed here by the user (not tracked by Git).
    *   `templates/`: Standard Flask directory for Jinja2 HTML templates.
    *   `.env.example`: Template for required environment variables.
    *   `requirements.txt`: Lists Python package dependencies for `pip install -r requirements.txt`.
*   **`.env`**: Stores actual secrets and configuration. **Crucially, this file should be listed in `.gitignore` and never committed to version control.**
*   **`documentation/`**: Project documentation and tracking files.
*   **`README.md`**: Main project documentation: overview, setup, usage.
