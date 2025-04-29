# Updating the Reverse Proxy Auth Gateway

This document outlines the process for updating components of the Backend Duo authentication gateway, covering both development and production (Gunicorn/Wheel-based) deployment scenarios.

## Why This Update Method?

The production deployment method described in `README.md` utilizes pre-built Python wheels (`.whl` files). This approach offers several advantages:

1.  **Offline Installation:** Once the wheels are built (on a machine with internet/proxy access), the deployment server does *not* need internet connectivity or proxy configuration to install Python dependencies. This enhances security and simplifies deployment in restricted environments.
2.  **Consistency:** Building wheels ensures that the exact versions of dependencies tested during development are deployed, minimizing unexpected issues caused by version mismatches.
3.  **Simplified Rollback (Potentially):** Keeping previous wheel sets allows for quicker rollbacks if an update introduces problems.

This method decouples the *application code* updates from *dependency* updates. You can update the Flask application logic without necessarily rebuilding all the wheels, and vice-versa.

## Components Most Likely Requiring Updates

Security vulnerabilities are most frequently discovered in:

1.  **Nginx:** Keep the webserver patched against known exploits. Updates typically come from the OS package manager.
2.  **Python:** The underlying interpreter should be kept up-to-date, especially for security patches. Updates usually come from the OS package manager or by installing a newer version.
3.  **Flask and Core Dependencies (`Flask-Login`, `Flask-WTF`, `Werkzeug`, `Jinja2`, etc.):** Vulnerabilities can exist in the web framework or its core components. Updates require updating `requirements.txt` and rebuilding wheels.
4.  **Authentication Libraries (`ldap3`, `duo_universal_python`):** Security issues or necessary updates related to AD interactions or Duo API changes will require updating these libraries via `requirements.txt` and rebuilding wheels.
5.  **Operating System:** General OS updates patch underlying libraries (like OpenSSL) and system components.

## Update Procedures

### Scenario 1: Development Environment (Local `flask run` or `python -m flask_auth.app`)

1.  **Update Application Code:** Pull the latest code changes from your Git repository.
2.  **Update Dependencies:**
    *   Activate the virtual environment: `source venv/bin/activate`
    *   Check `requirements.txt` for any version changes.
    *   Install updated dependencies: `pip install -r flask_auth/requirements.txt` (Use `--proxy` if needed for pip).
3.  **Restart Flask:** Stop the running development server (Ctrl+C) and restart it: `python -m flask_auth.app`.

### Scenario 2: Production Environment (Gunicorn + Wheels + Systemd)

This process mirrors the "Preparation" and "Deployment" steps in the `README.md`.

**A. Preparation (On a machine with internet/proxy access):**

1.  **Get Latest Code:** Pull the latest application code changes (`git pull`).
2.  **Update `requirements.txt`:** Modify `flask_auth/requirements.txt` if specific dependency versions need to be changed.
3.  **Clean & Rebuild Wheels:**
    ```bash
    rm -rf wheels
    mkdir wheels
    # Use proxy if needed for pip wheel command
    pip wheel --proxy <your-proxy> --wheel-dir=wheels -r flask_auth/requirements.txt
    # Or without proxy:
    # pip wheel --wheel-dir=wheels -r flask_auth/requirements.txt
    ```
4.  **Package:** Bundle the updated application code, the new `wheels/` directory, and the production `.env` file.

**B. Deployment (On the server, typically as root):**

1.  **Stop Service:** `systemctl stop backend-duo.service`
2.  **Backup (Optional but Recommended):** Create a backup of the current `/opt/backend-duo` directory.
3.  **Replace Files:**
    *   Remove the old contents: `rm -rf /opt/backend-duo/*` (Be careful!)
    *   Extract the new package contents into `/opt/backend-duo/`.
    *   Ensure `.env` has correct production values and no inline comments.
4.  **Set Ownership:** `chown -R www-data:www-data /opt/backend-duo` (Adjust user/group if needed).
5.  **Recreate/Update Virtual Environment:**
    *   If Python version hasn't changed drastically, you might reuse the venv structure. If unsure, remove and recreate:
        ```bash
        rm -rf /opt/backend-duo/venv
        python3 -m venv /opt/backend-duo/venv
        chown -R www-data:www-data /opt/backend-duo/venv
        ```
6.  **Install from New Wheels:**
    ```bash
    /opt/backend-duo/venv/bin/pip install --no-index --find-links=/opt/backend-duo/wheels -r /opt/backend-duo/flask_auth/requirements.txt
    ```
7.  **Restart Service:**
    ```bash
    systemctl daemon-reload # Important if systemd file *itself* or .env changed
    systemctl start backend-duo.service
    ```
8.  **Update Nginx/OS (If Necessary):** Use your OS package manager (e.g., `apt update && apt upgrade nginx`, `yum update nginx`) to update Nginx or other system packages. Reload or restart Nginx if its configuration or binaries changed (`systemctl reload nginx`).
9.  **Verification:** Check service status (`systemctl status backend-duo.service`), logs (`journalctl -u backend-duo.service`), and test the application thoroughly. 