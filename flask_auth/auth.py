import os
from ldap3 import Server, Connection, ALL, NTLM, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPException
import ssl # Import ssl for TLS context
import logging # Import logging

# --- LDAP3 Debug Logging --- #
# Uncomment these lines for detailed ldap3 debug output
# import sys
# ldap3_logger = logging.getLogger('ldap3')
# ldap3_logger.setLevel(logging.DEBUG)
# # Send ldap3 logs to standard output (or adjust handler as needed)
# ldap3_log_handler = logging.StreamHandler(sys.stdout)
# ldap3_log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# ldap3_log_handler.setFormatter(ldap3_log_formatter)
# ldap3_logger.addHandler(ldap3_log_handler)
# --- End LDAP3 Debug Logging ---

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- BEGIN ADDED DEBUG FLAG ---
# Read debug flag from environment (defaults to False)
FLASK_APP_DEBUG = os.environ.get('FLASK_APP_DEBUG', 'false').lower() == 'true'
if FLASK_APP_DEBUG:
    logger.info("Flask app debug logging enabled via FLASK_APP_DEBUG=true")
# --- END ADDED DEBUG FLAG ---

# Load AD configuration from environment variables
# AD_SERVER = os.environ.get('AD_SERVER') # Old
AD_SERVER_URIS = os.environ.get('AD_SERVER_URIS') # New: Use URIS
AD_PORT = int(os.environ.get('AD_PORT', 636)) # Default to LDAPS port
AD_USE_SSL = os.environ.get('AD_USE_SSL', 'true').lower() == 'true'
# --- BEGIN UPDATED DEBUG LOGGING ---
if FLASK_APP_DEBUG:
    raw_ad_use_ssl_env = os.environ.get('AD_USE_SSL')
    logger.info(f"DEBUG: Raw AD_USE_SSL from env: '{raw_ad_use_ssl_env}', Type: {type(raw_ad_use_ssl_env)}")
    logger.info(f"DEBUG: Processed AD_USE_SSL boolean: {AD_USE_SSL}, Type: {type(AD_USE_SSL)}")
# --- END UPDATED DEBUG LOGGING ---
# AD_BASE_DN = os.environ.get('AD_BASE_DN') # Old
AD_SEARCH_BASE = os.environ.get('AD_SEARCH_BASE') # New: Use SEARCH_BASE
# Optional bind user for searching/initial connection (if needed)
# AD_BIND_USER = os.environ.get('AD_BIND_USER') # Old - Using DN directly now
AD_BIND_DN = os.environ.get('AD_BIND_DN') # New: Use BIND_DN
AD_BIND_PASSWORD = os.environ.get('AD_BIND_PASSWORD')

def check_ad_config():
    """Checks if required AD configuration variables are set."""
    # required_vars = ['AD_SERVER_URIS', 'AD_SEARCH_BASE'] # Old
    required_vars = ['AD_SERVER_URIS', 'AD_SEARCH_BASE', 'AD_BIND_DN', 'AD_BIND_PASSWORD'] # New: Add bind credentials
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        logger.error(f"Missing AD configuration environment variables: {', '.join(missing_vars)}. Service account bind is required.")
        return False
    return True

def connect_ad():
    """
    Establishes a connection to the Active Directory server.
    Uses service account bind credentials if provided, otherwise attempts anonymous bind.

    Returns:
        ldap3.Connection: An active LDAP connection object or None if connection fails.
    Raises:
        LDAPSocketOpenError: If connection to the server fails.
        LDAPBindError: If binding with service account fails.
        Exception: For other unexpected errors.
    """
    if not check_ad_config():
        raise ValueError("AD configuration is missing required service account bind details.")

    # Handle comma-separated URIs, use the first one for now
    server_uri_list = [uri.strip() for uri in AD_SERVER_URIS.split(',') if uri.strip()]
    if not server_uri_list:
        logger.error("AD_SERVER_URIS is empty or invalid.")
        raise ValueError("AD server URI configuration is invalid.")

    ad_server_host = server_uri_list[0] # Use the first server
    if len(server_uri_list) > 1:
        logger.warning(f"Multiple AD server URIs found in AD_SERVER_URIS. Using the first one: {ad_server_host}")

    # Remove potential ldap:// or ldaps:// prefix for Server() object if present
    # and handle potential port in the URI string itself
    if "://" in ad_server_host:
        ad_server_host = ad_server_host.split("://")[1]
    # Check if port is in the host string itself (e.g., server.com:636)
    if ":" in ad_server_host:
        host_part, port_part = ad_server_host.split(":", 1)
        try:
            connection_port = int(port_part)
            ad_server_host = host_part
        except ValueError:
            logger.warning(f"Could not parse port from AD_SERVER_URIS entry '{server_uri_list[0]}'. Using default/configured AD_PORT: {AD_PORT}")
            connection_port = AD_PORT
    else:
        connection_port = AD_PORT # Use the AD_PORT env var if not in the URI

    tls_config = None
    use_ssl_flag = False # Default to False
    if AD_USE_SSL:
        # Determine if SSL should be used based on the port or the AD_USE_SSL var
        # Typically 636 implies SSL, 389 implies non-SSL, but AD_USE_SSL is explicit
        # logger.info(f"AD_USE_SSL is True. Configuring TLS for connection to {ad_server_host}:{connection_port}.")
        # tls_config = Tls(validate=ssl.CERT_NONE) # Use CERT_REQUIRED in production # Old CERT_NONE logic
        # Ensure use_ssl=True is passed if TLS is configured
        # use_ssl_flag = True

        # --- New CA Cert Validation Logic ---
        ca_cert_path = os.environ.get('AD_CA_CERT_FILE')
        if ca_cert_path:
            if os.path.exists(ca_cert_path):
                logger.info(f"AD_USE_SSL is True. Configuring TLS with CERT_REQUIRED using CA file: {ca_cert_path}")
                tls_config = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_cert_path)
                use_ssl_flag = True
            else:
                logger.error(f"AD_CA_CERT_FILE '{ca_cert_path}' not found! Falling back to CERT_NONE (insecure). Check path.")
                tls_config = Tls(validate=ssl.CERT_NONE)
                use_ssl_flag = True # Still use SSL, just without validation
        else:
            logger.warning("AD_USE_SSL is True, but AD_CA_CERT_FILE environment variable is not set. Falling back to CERT_NONE (insecure). Consider setting AD_CA_CERT_FILE.")
            tls_config = Tls(validate=ssl.CERT_NONE)
            use_ssl_flag = True
        # --- End New CA Cert Validation Logic ---
    else:
        # If AD_USE_SSL is False, ensure we don't use SSL
        logger.info(f"AD_USE_SSL is False. Connecting without TLS to {ad_server_host}:{connection_port}.")
        use_ssl_flag = False


    # server = Server(AD_SERVER, port=AD_PORT, use_ssl=AD_USE_SSL, tls=tls_config, get_info=ALL) # Old
    server = Server(ad_server_host, port=connection_port, use_ssl=use_ssl_flag, tls=tls_config, get_info=ALL) # New

    # user = AD_BIND_USER if AD_BIND_USER else None # Old
    user = AD_BIND_DN # Directly use the required bind DN
    password = AD_BIND_PASSWORD # Directly use the required bind password
    # password = AD_BIND_PASSWORD if AD_BIND_DN and AD_BIND_PASSWORD else None # Old check

    logger.info(f"Attempting to connect and bind as service account: {user}") # Log service account bind attempt
    try:
        conn = Connection(server, user=user, password=password, auto_bind=True)
        logger.info(f"Successfully connected and bound to AD server {ad_server_host}:{connection_port} as service account {user}")
        return conn
    except LDAPBindError as bind_e:
        logger.error(f"Failed to bind using service account DN '{user}'. Check AD_BIND_DN and AD_BIND_PASSWORD. Error: {bind_e}")
        raise # Re-raise the specific error after logging
    except LDAPSocketOpenError as sock_e:
        logger.error(f"Failed to connect to AD server {ad_server_host}:{connection_port}. Error: {sock_e}")
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during service account connection to {ad_server_host}:{connection_port}: {e}")
        raise

def find_user_dn(conn, username):
    """
    Searches for the user's Distinguished Name (DN) using the provided connection.

    Args:
        conn (ldap3.Connection): An active, bound LDAP connection.
        username (str): The username (e.g., sAMAccountName) to search for.

    Returns:
        str: The user's full DN or None if not found.
    Raises:
        LDAPException: If an LDAP error occurs during the search.
        Exception: For other unexpected errors.
    """
    # search_filter = f'(sAMAccountName={username})' # Old, assuming sAMAccountName
    # Use the filter from the environment variable
    user_filter_template = os.environ.get('AD_USER_FILTER', '(sAMAccountName={username})') # Default if not set
    try:
        search_filter = user_filter_template.format(username=username)
    except KeyError:
        logger.error(f"Invalid AD_USER_FILTER template: '{user_filter_template}'. Missing '{{username}}' placeholder?")
        raise ValueError("Invalid AD user filter configuration.")

    # conn.search(search_base=AD_BASE_DN, # Old
    conn.search(search_base=AD_SEARCH_BASE, # New: Use AD_SEARCH_BASE
                search_filter=search_filter,
                attributes=['objectClass']) # New: Request a minimal, common attribute

    if conn.entries:
        user_entry = conn.entries[0]
        logger.info(f"Found DN for user '{username}': {user_entry.entry_dn}")
        return user_entry.entry_dn
    else:
        # logger.warning(f"User '{username}' not found in AD with filter '{search_filter}' under base DN '{AD_BASE_DN}'.") # Old
        logger.warning(f"User '{username}' not found in AD with filter '{search_filter}' under base DN '{AD_SEARCH_BASE}'.") # New
        return None

def verify_ad_user(username, password):
    """
    Verifies a user's credentials against Active Directory using the correct service account flow.

    Args:
        username (str): The username (e.g., sAMAccountName) entered by the user.
        password (str): The password entered by the user.

    Returns:
        tuple[bool, str | None]: A tuple containing:
            - bool: True if authentication is successful, False otherwise.
            - str | None: An error type ('invalid_credentials', 'connection_error', 'search_error', 'config_error', 'other_error') or None on success.
    """
    if not check_ad_config(): # Check now includes bind DN/Password
        return False, 'config_error'
    if not username or not password:
        logger.error("Username and password cannot be empty.")
        return False, 'other_error' # Or perhaps 'invalid_credentials'?

    service_conn = None
    user_dn = None

    try:
        # --- Step 1: Connect using Service Account ---
        logger.info(f"Attempting to connect with service account to verify user: {username}")
        service_conn = connect_ad() # This now requires and uses AD_BIND_DN/Password

        # --- Step 2: Search for the User's DN using the service account connection ---
        logger.info(f"Service account connected. Searching for user DN for: {username}")
        user_dn = find_user_dn(service_conn, username)

        if not user_dn:
            # User not found by the search filter and base DN
            logger.warning(f"User '{username}' not found in AD search using service account.")
            return False, 'invalid_credentials' # Treat user not found as invalid credentials

        # --- Step 3: User DN Found - Unbind Service Account ---
        logger.info(f"Found user DN: {user_dn}. Unbinding service account.")
        service_conn.unbind()
        service_conn = None # Clear the connection object

        # --- Step 4: Attempt to Bind as the User --- #
        logger.info(f"Attempting to bind with found user DN '{user_dn}' and provided password.")

        # Re-create server object details (could be refactored into a helper)
        server_uri_list = [uri.strip() for uri in AD_SERVER_URIS.split(',') if uri.strip()]
        if not server_uri_list: raise ValueError("AD server URI configuration is invalid.") # Should not happen if config check passed
        ad_server_host = server_uri_list[0]
        if "://" in ad_server_host: ad_server_host = ad_server_host.split("://")[1]
        if ":" in ad_server_host:
             host_part, port_part = ad_server_host.split(":", 1)
             try:
                 connection_port = int(port_part)
                 ad_server_host = host_part
             except ValueError:
                 connection_port = AD_PORT
        else:
             connection_port = AD_PORT

        tls_config_user = None
        use_ssl_flag_user = False
        if AD_USE_SSL:
             # tls_config_user = Tls(validate=ssl.CERT_NONE) # Old CERT_NONE
             # use_ssl_flag_user = True
             # --- New CA Cert Validation Logic (for user bind) ---
             ca_cert_path = os.environ.get('AD_CA_CERT_FILE')
             if ca_cert_path:
                 if os.path.exists(ca_cert_path):
                     logger.info(f"User Bind: AD_USE_SSL is True. Configuring TLS with CERT_REQUIRED using CA file: {ca_cert_path}")
                     tls_config_user = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_cert_path)
                     use_ssl_flag_user = True
                 else:
                     logger.error(f"User Bind: AD_CA_CERT_FILE '{ca_cert_path}' not found! Falling back to CERT_NONE (insecure). Check path.")
                     tls_config_user = Tls(validate=ssl.CERT_NONE)
                     use_ssl_flag_user = True # Still use SSL, just without validation
             else:
                 logger.warning("User Bind: AD_USE_SSL is True, but AD_CA_CERT_FILE environment variable is not set. Falling back to CERT_NONE (insecure). Consider setting AD_CA_CERT_FILE.")
                 tls_config_user = Tls(validate=ssl.CERT_NONE)
                 use_ssl_flag_user = True
             # --- End New CA Cert Validation Logic ---
        else:
            logger.info(f"User Bind: AD_USE_SSL is False. Connecting without TLS to {ad_server_host}:{connection_port}.")
            use_ssl_flag_user = False

        user_server = Server(ad_server_host, port=connection_port, use_ssl=use_ssl_flag_user, tls=tls_config_user, get_info=None)

        # Try connecting and binding as the actual user
        with Connection(user_server, user=user_dn, password=password, auto_bind=True) as user_conn:
            # If auto_bind=True succeeds without raising an exception, the password is correct for the found user DN
            logger.info(f"Successfully authenticated user '{username}' by binding with their DN '{user_dn}'.")
            return True, None # Authentication successful!

    except LDAPBindError as bind_e:
        # This error could be from connect_ad (service account) or the user bind attempt
        if service_conn and service_conn.bound:
            # Error must have happened during the user bind attempt (Step 4)
             logger.warning(f"Authentication failed for user '{username}' (DN: '{user_dn}'). Invalid credentials provided. Error: {bind_e}")
             return False, 'invalid_credentials'
        else:
            # Error happened during the service account bind (Step 1)
             logger.error(f"Service account bind failed. Cannot proceed with user authentication. Check service account credentials. Error: {bind_e}")
             return False, 'config_error' # Treat service account failure as config error

    except (LDAPSocketOpenError, ConnectionRefusedError) as conn_e:
        # Error connecting to the AD server itself (could happen at Step 1 or Step 4)
        server_uri_list = [uri.strip() for uri in AD_SERVER_URIS.split(',') if uri.strip()]
        ad_host_port_str = f"{AD_SERVER_URIS} (default port {AD_PORT})"
        if server_uri_list: # Format a more specific host/port string
             # (Logic to parse host/port from URI - duplicate from above, could be refactored)
             ad_server_host = server_uri_list[0]
             if "://" in ad_server_host: ad_server_host = ad_server_host.split("://")[1]
             if ":" in ad_server_host:
                 ad_host_port_str = server_uri_list[0]
             else:
                 ad_host_port_str = f"{ad_server_host}:{AD_PORT}"

        logger.error(f"Error connecting to AD server {ad_host_port_str}. Check host/port/firewall. Error: {conn_e}")
        return False, 'connection_error'

    except LDAPException as ldap_e:
        # Other LDAP errors, likely during the search (Step 2)
        logger.error(f"An LDAP error occurred, likely during user search for '{username}'. Error: {ldap_e}")
        return False, 'search_error'

    except ValueError as val_e:
        # Catch potential config issues (e.g., invalid filter format)
        logger.error(f"Configuration error during AD authentication: {val_e}")
        return False, 'config_error'

    except Exception as e:
        # Catch-all for unexpected errors
        logger.exception(f"An unexpected error occurred during AD authentication process for user '{username}': {e}")
        return False, 'other_error'

    finally:
        # Ensure the service connection is always unbound if it exists and is bound
        if service_conn and service_conn.bound:
            logger.debug("Unbinding service account connection in finally block.")
            service_conn.unbind()

# Example usage (for testing purposes, remove later)
if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv() # Load .env file from current directory

    # Test user verification
    test_user = input("Enter AD username to test: ")
    # Consider using getpass for password input in a real script
    import getpass
    test_pass = getpass.getpass(f"Enter password for {test_user}: ")
    success, error_type = verify_ad_user(test_user, test_pass)
    if success:
        print(f"\nAuthentication successful for {test_user}")
    else:
        print(f"\nAuthentication failed for {test_user}. Error type: {error_type}") 