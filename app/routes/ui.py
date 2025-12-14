from flask import Blueprint, render_template, session, redirect, url_for

ui_bp = Blueprint("ui", __name__)

@ui_bp.route("/")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("auth.login"))
    return render_template("dashboard.html")
