## Overview

This project implements a secure authentication gateway placed in front of a legacy Java application running on Apache Tomcat. It utilizes Nginx as a reverse proxy and a custom Flask application to handle user authentication. The authentication process involves primary validation against Active Directory (AD) and secondary validation using Duo Security's Multi-Factor Authentication (MFA) via the Duo Universal Prompt Web SDK. The primary goal is to enhance security for the legacy application without requiring modifications to its codebase.

## Goals

* Secure access to the legacy Tomcat application, preventing direct user access.
* Implement a robust, custom authentication layer using Flask.
* Integrate with Active Directory for primary user credential verification.
* Integrate with Duo Security using the official Duo Universal Prompt Python SDK for MFA.
* Utilize Nginx as the reverse proxy to manage traffic flow.
* No SSL is required due to terminating the application on the load balancer.  The app will be wrapped in SSL for production.  Testing will be done against nginx port 80 directly.
* Provide a seamless login experience for authorized users.
* Avoid the need for the separate Duo Authentication Proxy application.


## Functional Requirements

* **FR1: Reverse Proxy:** Nginx must listen on standard ports 80 and handle incoming user requests.
* **FR2: Unauthenticated Access:** Requests from unauthenticated users to protected resources must be redirected to the Flask login page.
* **FR3: Login Interface:** The Flask application must present a clean HTML login form requesting username and password.
* **FR4: Active Directory Authentication:** The Flask application must securely validate user-submitted credentials against the configured Active Directory service using LDAPS.
* **FR5: Duo MFA Trigger:** Upon successful AD authentication, the Flask application must initiate the Duo MFA flow using the `duo_universal_python` SDK.
* **FR6: Duo Interaction:** The system must correctly redirect the user to Duo's Universal Prompt and handle the callback upon completion.
* **FR7: Session Management:** Upon successful AD and Duo authentication, the Flask application must establish a secure user session (e.g., using signed cookies via Flask-Login or Flask-Session).
* **FR8: Authenticated Proxying:** Nginx must verify the user's authenticated session (potentially via Flask `auth_request`) before proxying requests to the backend Tomcat application running on `localhost:8080`.
* **FR9: Logout:** Provide a mechanism for users to explicitly log out, terminating their session.
* **FR10: Configuration:** Sensitive information (AD credentials, Duo keys, Flask secret key) must be configurable via environment variables or a `.env` file, not hardcoded.  The web application should be reachable internally or externally via a specific URL (e.g., `https://backend.your-company.com`). The app can use a web proxy for the Duo Universal Prompt.  Defining the cookie session lengths.


## Non-Functional Requirements

* **NFR1: Security:**
    * Session cookies must be flagged HttpOnly, Secure, and SameSite.
    * Credentials (AD bind user, Duo keys, Flask secret) must be stored and accessed securely.
    * Protect against common web vulnerabilities (CSRF, XSS).
* **NFR2: Performance:** The authentication process should introduce minimal latency for the end-user.
* **NFR3: Reliability:** The system should handle authentication failures gracefully (e.g., incorrect password, Duo denial) and provide informative feedback to the user. Nginx should handle backend Tomcat unavailability appropriately.
* **NFR4: Maintainability:** Flask code should be modular (e.g., separating routes, auth logic, utilities) and follow specified coding standards (`black`, PEP8). Nginx configuration should be well-commented.

## Future Considerations

* Add detailed audit logging for authentication attempts.
* Support for multiple backend applications behind the same gateway.

# Duo Security Integration

*   Duo Account: Access to a Duo account with an administrative role.
*   Application Setup: An application configured in the Duo Admin Panel (likely a "Web SDK" type).
    *   Integration Key (ikey)
    *   Secret Key (skey)
    *   API Hostname (apihost)
*   Python SDK: `duo-universal` library.

## System Prerequisites (Ubuntu 22.04)

The following system packages are required on Ubuntu 22.04 LTS for building Python dependencies:

*   `libldap2-dev`: Required for compiling the `python-ldap` package.
*   `libsasl2-dev`: Required for SASL support within `python-ldap`.

To install them, run:
\`\`\`bash
sudo apt-get update && sudo apt-get install -y libldap2-dev libsasl2-dev
\`\`\`

*   **CA Certificate for LDAPS (If Using Internal CA):** If your Active Directory LDAPS uses a certificate signed by an internal Certificate Authority (CA) not trusted by default by the operating system, you must install the CA certificate on the machine running the Flask application.
    *   Place your CA certificate file (in `.crt` or `.pem` format) in the directory: `/usr/local/share/ca-certificates/`
    *   After copying the certificate, run the command: `sudo update-ca-certificates`
    *   Ensure the path to this CA certificate is specified in the `AD_CA_CERT_FILE` environment variable if you intend to use strict validation (`validate=ssl.CERT_REQUIRED` in `flask_auth/auth.py`).

## Environment Variables

### Proxy Configuration

If the server environment where the Flask application runs requires an HTTP/HTTPS proxy for outbound internet access (e.g., to reach the Duo Security API at `api-*.duosecurity.com`), standard proxy environment variables **must** be set.

The `duo-universal-python` library (and the underlying `requests` library) will automatically use these variables if present.

Set the following variables in the environment where the Flask application process runs (e.g., system-wide via `/etc/environment`, within a Docker container, or via a process manager like systemd):

*   **`HTTP_PROXY`**: The URL of the proxy for HTTP requests.
    *   Example: `HTTP_PROXY="http://your-proxy.internal:8080"`
    *   Example with auth: `HTTP_PROXY="http://user:pass@your-proxy.internal:8080"`
*   **`HTTPS_PROXY`**: The URL of the proxy for HTTPS requests. Often the same as `HTTP_PROXY`.
    *   Example: `HTTPS_PROXY="http://your-proxy.internal:8080"`
    *   Example with auth: `HTTPS_PROXY="http://user:pass@your-proxy.internal:8080"`
*   **`NO_PROXY`**: A comma-separated list of hostnames, domains, or IP addresses/subnets that should **not** be accessed via the proxy (e.g., internal resources, localhost).
    *   Example: `NO_PROXY="localhost,127.0.0.1,.internal-domain.com,192.168.1.0/24"`

**Note:** It's often recommended to define both uppercase (`HTTPS_PROXY`) and lowercase (`https_proxy`) versions, as some applications may check for one or the other.

Failure to configure the proxy correctly in environments that require it will likely result in connection timeouts when the Flask application attempts to contact Duo's API.

### Required Variables

*   `FLASK_SECRET_KEY`: A long, random string used for session signing.
*   `AD_SERVER_URIS`: Comma-separated list of LDAPS URIs (e.g., `ldaps://ad-server1.your-company.com:636,ldaps://ad-server2.your-company.com:636`).
*   `AD_BIND_USER_DN`: The full Distinguished Name (DN) of the service account for binding.
*   `AD_BIND_USER_PASSWORD`: The password for the AD service account.
*   `AD_SEARCH_BASE`: The base DN for searching user accounts (e.g., `OU=Users,DC=example,DC=com`).
*   `AD_CA_CERT_FILE` (Optional but Recommended): Path to the CA certificate file used to validate the AD server's LDAPS certificate. Required if using an internal CA.
*   `DUO_CLIENT_ID`: Duo application Client ID (Integration Key).
*   `DUO_CLIENT_SECRET`: Duo application Client Secret (Secret Key).
*   `DUO_API_HOST`: Duo application API Hostname.
*   `DUO_REDIRECT_URI`: The full callback URL registered with Duo (e.g., `https://your.domain/duo_callback`).