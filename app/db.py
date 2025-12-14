from flask import current_app, g
from pymongo import MongoClient

def get_db():
    """
    Get a MongoDB database instance for the current request.
    Uses Flask's 'g' object to store it during the request.
    """
    if "db" not in g:
        mongo_uri = current_app.config["MONGO_URI"]
        client = MongoClient(mongo_uri)
        g.db = client["cloudtrail_db"]  # database name
    return g.db

def init_db(app):
    """
    Initialize DB by attaching a teardown function
    that closes the connection after each request.
    """
    @app.teardown_appcontext
    def close_db(exception):
        db = g.pop("db", None)
        if db is not None:
            db.client.close()
