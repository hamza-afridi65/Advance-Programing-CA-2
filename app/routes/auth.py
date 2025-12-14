from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__)

def _stored_password_hash():
    """
    Use hashed password if provided (best practice), else hash plain password once per app run.
    """
    pwd_hash = current_app.config.get("ADMIN_PASSWORD_HASH")
    if pwd_hash:
        return pwd_hash

    if not hasattr(current_app, "_cached_admin_pwd_hash"):
        current_app._cached_admin_pwd_hash = generate_password_hash(current_app.config["ADMIN_PASSWORD"])
    return current_app._cached_admin_pwd_hash

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("ui.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username != current_app.config["ADMIN_USERNAME"]:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        if not check_password_hash(_stored_password_hash(), password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["user"] = username
        return redirect(url_for("ui.dashboard"))

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("auth.login"))
