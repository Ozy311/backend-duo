from flask import Flask, render_template, request, flash, redirect, url_for, session
import os
from dotenv import load_dotenv
# Import only AD functions and the auth logger from auth.py
from .auth import verify_ad_user, logger as auth_logger
from .models import User
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
# Import Duo client and exceptions
from duo_universal import Client
from duo_universal import DuoException
import secrets
import logging # Add logging
from datetime import timedelta # <<< ADD THIS IMPORT
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Basic Logging Setup ---
# Use a file handler in production potentially
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Simplier setup for now, prints to stderr/stdout where Flask runs
# REMOVED: logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
# REMOVED: app_logger = logging.getLogger(__name__) # Use Flask app's logger or a dedicated one
# Use Flask's built-in logger instead, configured by app.run(debug=True)

# Configure Flask secret key from environment variable for session/flash support
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    # Use app.logger here (it's available after app = Flask(__name__))
    app.logger.warning("FLASK_SECRET_KEY not set in environment. Using default, insecure key for dev.")
    app.config['SECRET_KEY'] = 'default-insecure-secret-key-for-dev' # Ensure this is set for flash messages

# Configure Session Lifetime from Environment Variable
session_hours_str = os.environ.get('FLASK_SESSION_DURATION_HOURS', '21') # Default 21 hours
try:
    session_hours = float(session_hours_str)
    if session_hours <= 0:
        app.logger.warning(f"FLASK_SESSION_DURATION_HOURS ({session_hours_str}) is zero or negative. Session will expire immediately or use Flask default session cookie behavior.")
        # Let Flask handle default session cookie (non-permanent) if duration is invalid/non-positive
        app.config['SESSION_PERMANENT'] = False
    else:
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=session_hours)
        app.config['SESSION_PERMANENT'] = True # Make sessions permanent by default IF lifetime is set
        app.logger.info(f"Flask session lifetime set to {session_hours} hours.")
except ValueError:
    app.logger.error(f"Invalid value for FLASK_SESSION_DURATION_HOURS: '{session_hours_str}'. Using Flask default session cookie behavior.")
    app.config['SESSION_PERMANENT'] = False # Ensure sessions are not permanent if value is invalid

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
# If a user tries to access a @login_required page without being logged in,
# Flask-Login redirects them here.
login_manager.login_view = "login_get"
login_manager.login_message_category = "info" # Optional: category for the flash message

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login hook to load a user from the session."""
    # Since we're not using a database, just recreate the User object
    # In a real app, you might query a database here based on user_id
    app.logger.debug(f"Flask-Login: Loading user with ID: {user_id}") # Use app.logger
    return User(user_id)
# --- End Flask-Login Setup ---

# --- Duo Client Initialization ---
duo_client = None
try:
    duo_client = Client(
        client_id=os.environ.get('DUO_CLIENT_ID'),
        client_secret=os.environ.get('DUO_CLIENT_SECRET'),
        host=os.environ.get('DUO_API_HOST'),
        redirect_uri=os.environ.get('DUO_REDIRECT_URI') # Ensure this matches your Duo app config and Nginx setup (e.g., https://yourdomain/duo_callback)
    )
    # Add basic check
    if not all([os.environ.get('DUO_CLIENT_ID'), os.environ.get('DUO_CLIENT_SECRET'), os.environ.get('DUO_API_HOST'), os.environ.get('DUO_REDIRECT_URI')]):
        app.logger.warning("One or more DUO environment variables are missing. Duo functionality will likely fail.")
        # Optionally set duo_client back to None or raise an error if it's critical
        # duo_client = None
except Exception as e:
    app.logger.exception(f"Failed to initialize Duo Client: {e}")
    # duo_client remains None
# --- End Duo Client Initialization ---

# --- Define LoginForm --- Necessary for CSRF and structure
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login') # Though we don't use it in the template directly, it's good practice
# --- End LoginForm Definition ---

@app.route('/')
@login_required # Protect the index route
def index():
    # Now current_user is available via Flask-Login
    return f"Flask Auth Gateway - Logged in as {current_user.id}. Go to /logout to log out."

@app.route('/login', methods=['GET'])
def login_get():
    """Serves the login page."""
    if current_user.is_authenticated:
        app.logger.info(f"User {current_user.id} already authenticated. Redirecting to index.") # Use app.logger
        return redirect(url_for('index')) # Redirect if already logged in
    form = LoginForm() # Create an instance of the form
    return render_template('login.html', form=form) # Pass the form to the template

# Placeholder for POST, AD/Duo logic will go here
@app.route('/login', methods=['POST'])
def login_post():
    """Handles login form submission, AD check, and initiates Duo auth."""
    username = request.form.get('username')
    password = request.form.get('password')

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if not username or not password:
        flash('Username and password are required.', 'warning') # Use warning category
        return redirect(url_for('login_get'))

    app.logger.info(f"Attempting AD authentication for user: {username}") # Use app.logger

    # Use the modified AD verification function
    ad_success, ad_error_type = verify_ad_user(username, password)

    if ad_success:
        app.logger.info(f"AD authentication successful for user: {username}")

        # --- Initiate Duo Flow ---
        try:
            state = secrets.token_hex(16) # Generate secure state for this auth attempt
            session['duo_state'] = state   # Store state in user's session
            session['duo_username'] = username # Store username for callback verification
            # Store the original redirect URI if present, otherwise default to index
            original_uri = request.args.get('redirect_uri', url_for('index')) # Get potential redirect URI
            session['redirect_uri'] = original_uri
            app.logger.info(f"Storing potential redirect URI in session: {original_uri}") # <<< ADD LOGGING
            app.logger.info(f"Generated Duo state for {username}: {state[:6]}... (Storing in session)") # Use app.logger
            # app.logger.info(f"Storing redirect URI: {session['redirect_uri']}") # Log the redirect URI - Redundant with above log

            if not duo_client:
                 # Log the error, flash a generic message to the user
                 app.logger.error("Duo client not initialized!") 
                 flash('Authentication service unavailable. Please try again later.', 'error')
                 return redirect(url_for('login_get'))

            # Ensure health check passes before generating URL
            try:
                health_check = duo_client.health_check()
                app.logger.info(f"Duo health check successful: {health_check}") # Use app.logger
            except DuoException as health_e:
                 # Keep auth_logger here? Assuming auth.py might have separate logging needs.
                 # Let's keep this one as auth_logger for now.
                 auth_logger.error(f"Duo health check failed: {health_e}")
                 flash('Multi-factor authentication service is currently unavailable. Please try again later.', 'error')
                 return redirect(url_for('login_get'))
            except Exception as health_e: # Catch potential network errors etc.
                 # Keep auth_logger here too?
                 auth_logger.exception(f"Unexpected error during Duo health check: {health_e}")
                 flash('An unexpected error occurred connecting to the authentication service.', 'error')
                 return redirect(url_for('login_get'))

            # Create auth URL
            auth_url = duo_client.create_auth_url(username, state)
            app.logger.info(f"Generated Duo auth URL for {username}.") # Use app.logger

            # Redirect to Duo
            app.logger.info(f"Redirecting user {username} to Duo...") # Use app.logger
            return redirect(auth_url)

        except DuoException as e:
             # Keep auth_logger?
             auth_logger.error(f"Duo SDK error creating auth URL for user {username}: {e}")
             # Flash a generic message unless it's a very specific, user-actionable error
             flash(f"Could not start multi-factor authentication. Please try again.", "error")
             return redirect(url_for('login_get'))
        except Exception as e:
            # Catch other potential errors during Duo initiation (e.g., session issues)
            app.logger.exception(f"Unexpected error initiating Duo auth for user {username}: {e}") # Use app.logger
            flash(f"An unexpected error occurred during authentication setup. Please contact support.", "error") # User-friendly message
            return redirect(url_for('login_get'))
        # --- End Duo Flow Initiation ---

    else:
        # Handle AD authentication failure based on error type
        app.logger.warning(f"AD authentication failed for user: {username}. Error type: {ad_error_type}") # Use app.logger
        if ad_error_type == 'invalid_credentials':
            flash('Invalid username or password.', 'error')
        elif ad_error_type == 'connection_error':
            flash('Could not connect to authentication server. Please try again later.', 'error')
        elif ad_error_type == 'config_error':
            flash('Authentication system configuration error. Please contact support.', 'error')
            # Maybe don't expose 'search_error' or 'other_error' directly
        else: # search_error, other_error, None (if verify_ad_user has unexpected path)
            flash('Authentication failed. Please try again.', 'error')

        return redirect(url_for('login_get')) # Redirect back to login page

# --- Nginx Auth Check Route ---
@app.route('/auth_check')
# @login_required # REMOVED: Causes 302 redirect, auth_request expects 401
def auth_check():
    """
    Endpoint for Nginx auth_request directive.
    Returns 200 OK if the user has a valid session (is authenticated via Flask-Login).
    Returns 401 Unauthorized otherwise.
    """
    # Log received cookies for debugging
    app.logger.debug(f"Auth check request cookies: {request.cookies}") # Use app.logger

    if current_user.is_authenticated:
        # User has a valid session cookie recognized by Flask-Login
        app.logger.debug(f"Auth check PASSED for user: {current_user.id}") # Use app.logger
        # You could add headers here if Nginx needs upstream user info:
        # from flask import Response
        # response = Response("OK", status=200)
        # response.headers['X-Authenticated-User'] = current_user.id
        # return response
        return "OK", 200
    else:
        # No valid session or user not authenticated
        app.logger.info("Auth check FAILED (unauthenticated)") # Use app.logger
        return "Unauthorized", 401
# --- End Nginx Auth Check Route ---

# Need a placeholder for the callback route
@app.route('/duo_callback')
def duo_callback():
    """Handles the redirect back from Duo after 2FA and logs the user in."""
    app.logger.info("Received request at /duo_callback") # Use app.logger

    # Retrieve state and username stored *before* redirecting to Duo
    state_from_session = session.pop('duo_state', None)
    username_from_session = session.pop('duo_username', None) # Retrieve associated username

    # Check for errors passed back from Duo in URL parameters first
    duo_error = request.args.get('error')
    duo_error_desc = request.args.get('error_description')
    if duo_error:
        app.logger.error(f"Duo error received in callback URL for user {username_from_session or 'unknown'}: {duo_error} - {duo_error_desc}") # Use app.logger
        flash(f"Multi-factor authentication error: {duo_error_desc or duo_error}", "error")
        # Clean up potentially lingering session vars even on error
        # session.pop('duo_state', None) # Already popped above
        # session.pop('duo_username', None)
        return redirect(url_for('login_get')) # Redirect back to login

    # Get parameters from Duo redirect
    state_from_duo = request.args.get('state')
    duo_code = request.args.get('duo_code')

    # --- State Validation ---
    app.logger.info(f"Callback State Check - Session: {state_from_session[:6] if state_from_session else 'None'}..., Duo URL: {state_from_duo[:6] if state_from_duo else 'None'}...") # Use app.logger
    if not state_from_session:
        app.logger.warning("No Duo state found in session during callback. Possible session expiry or flow issue.") # Use app.logger
        flash("Your session may have expired. Please try logging in again.", "warning")
        return redirect(url_for('login_get'))
    if not state_from_duo:
        app.logger.error("No state parameter received from Duo in callback URL.") # Use app.logger
        flash("Invalid response from authentication service. Please try logging in again.", "error")
        return redirect(url_for('login_get'))
    if state_from_session != state_from_duo:
        # CRITICAL: Log this with high severity
        app.logger.critical(f"Duo state mismatch error for user {username_from_session or 'unknown'}. Potential CSRF attack. Session state: {state_from_session}, Duo state: {state_from_duo}") # Use app.logger
        flash("Security error: State mismatch. Please try logging in again.", "error")
        # Ensure potentially compromised session state is cleared (already popped, but defensive)
        session.pop('duo_state', None)
        session.pop('duo_username', None)
        return redirect(url_for('login_get'))
    app.logger.info(f"Duo state validated successfully for user {username_from_session or 'unknown'}.") # Use app.logger
    # State is now validated and consumed
    # --- End State Validation ---

    # Also retrieve the original redirect URI
    redirect_uri_from_session = session.pop('redirect_uri', None)
    app.logger.info(f"Retrieved redirect URI from session: {redirect_uri_from_session}") # <<< ADD LOGGING

    if not duo_code:
        app.logger.error("Missing duo_code in callback URL.") # Use app.logger
        flash("Missing authorization code from multi-factor authentication. Please try again.", "error")
        return redirect(url_for('login_get'))

    if not username_from_session:
         # This *really* shouldn't happen if state validation passed and username was stored with state
         app.logger.error("CRITICAL: Missing username in session during callback, despite state validation succeeding.") # Use app.logger
         flash("Session data inconsistency. Please try logging in again.", "error")
         return redirect(url_for('login_get'))

    # Exchange code for 2FA result
    if not duo_client:
         # Keep auth_logger?
         auth_logger.error("Duo client not initialized during callback!")
         flash('Authentication service unavailable. Cannot complete multi-factor step.', 'error')
         return redirect(url_for('login_get'))

    try:
        app.logger.info(f"Attempting to exchange Duo code for user: {username_from_session}") # Use app.logger
        # Use the username retrieved from the *session* (associated with the validated state)
        decoded_token = duo_client.exchange_authorization_code_for_2fa_result(duo_code, username_from_session)

        # ---- Check Duo Result ----
        app.logger.info(f"Duo token exchange successful for user: {username_from_session}. Result: {decoded_token.get('auth_result', {}).get('result')}") # Use app.logger

        auth_result = decoded_token.get('auth_result', {})
        if auth_result.get('result') == 'allow':
            # User allowed MFA prompt
            app.logger.info(f"Duo access allowed for user: {username_from_session}") # Use app.logger

            # --- Flask-Login Integration ---
            # Create User object with the verified username
            user = User(username_from_session)
            # Explicitly mark the session as permanent *before* login_user
            session.permanent = True 
            # Log the user in using Flask-Login. This creates the persistent session cookie.
            # Temporarily remove remember=True to isolate session cookie behavior
            login_user(user) # REMOVED: remember=True
            app.logger.info(f"User {username_from_session} logged in via Flask-Login with configured session duration (no remember token).") # Updated log
            # --- End Flask-Login Integration ---
    
            # Determine the redirect target
            final_redirect_url = redirect_uri_from_session or url_for('index') # Fallback to index if URI wasn't in session
            app.logger.info(f"Determined final redirect URL (before sanity check): {final_redirect_url}") # <<< ADD LOGGING
            # Basic sanity check: prevent redirecting to external sites or non-relative paths if needed
            # Example: only allow relative paths starting with '/'
            if not final_redirect_url.startswith('/'):
                 app.logger.warning(f"Invalid redirect URI found ('{final_redirect_url}'), defaulting to index.") # Updated log
                 final_redirect_url = url_for('index')

            flash(f'Login and multi-factor authentication successful!', 'success') # Don't include username in flash
            app.logger.info(f"Redirecting successfully authenticated user {username_from_session} to: {final_redirect_url}") # Keep this log
            return redirect(final_redirect_url)
        else:
            # User denied, timed out, or other non-allow result
            result_status = auth_result.get('result', 'unknown')
            result_message = auth_result.get('status_msg', 'No specific reason provided.')
            app.logger.warning(f"Duo access denied or failed for user {username_from_session}. Result: {result_status}, Message: {result_message}") # Use app.logger
            # Provide a reasonably generic but informative message
            if result_status == 'deny':
                flash('Multi-factor authentication was denied.', 'error')
            else:
                flash(f'Multi-factor authentication failed: {result_message}', 'error')
            return redirect(url_for('login_get'))
        # ---- End Check Duo Result ----

    except DuoException as e:
        # Keep auth_logger?
        auth_logger.error(f"Duo SDK error exchanging code for user {username_from_session}: {e}")
        flash(f'Multi-factor authentication failed: {e}', 'error') # Can expose DuoException message usually
        return redirect(url_for('login_get'))
    except Exception as e:
        # Catch other unexpected errors (network, etc.)
        app.logger.exception(f"Unexpected error during Duo callback/exchange for {username_from_session}: {e}") # Use app.logger
        flash('An unexpected error occurred during multi-factor verification. Please try again or contact support.', 'error') # User-friendly
        return redirect(url_for('login_get'))

# --- Logout Route ---
@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    """Logs the current user out."""
    user_id = current_user.id # Get username before logging out
    logout_user() # Clears the user session (managed by Flask-Login)
    app.logger.info(f"User {user_id} logged out.") # Use app.logger
    flash("You have been logged out.", "info")
    return redirect(url_for('login_get'))
# --- End Logout Route ---

if __name__ == '__main__':
    # Note: Run with a production WSGI server (like Gunicorn or uWSGI) behind Nginx.
    # The debug flag should be False in production.
    # host='0.0.0.0' makes it accessible externally (within its network context)
    # The port should match what Nginx proxies to.
    # Flask's default logger is used if debug=True. Set explicitly if needed.
    app.logger.info("Starting Flask development server.") # Use app.logger
    app.run(debug=True, host='0.0.0.0', port=5000)

