from flask_login import UserMixin

class User(UserMixin):
    """
    Simple User class for Flask-Login session management.
    Does not interact with a database, just holds the user ID.
    """
    def __init__(self, id):
        self.id = id

    # Flask-Login requires get_id, which UserMixin provides based on self.id
    # Other UserMixin properties (is_authenticated, is_active, is_anonymous)
    # default to True, True, False respectively, which is suitable here. 