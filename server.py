#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 04 14:08:03 2022

@author: Hrishikesh Terdalkar
"""

###############################################################################

import datetime
from hashlib import md5
from flask import (
    Flask,
    render_template,
    redirect,
    jsonify,
    url_for,
    request,
    flash,
    session,
    Response,
    abort,
)
from flask_wtf import CSRFProtect
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy.sql.expression import func

import config
from models import db, User, Label, Sentence, Annotation

###############################################################################
# Import Sentences


def import_data():
    """Import Sentence Data into SQLite3 Database from CSV"""
    with open(config.DATA_FILE, encoding="utf-8") as f:
        rows = [
            line.split(",", 1) for line in f.read().split("\n") if line.strip()
        ]

    objects = [Sentence(headword=row[0], text=row[1]) for row in rows]
    db.session.add_all(objects)
    db.session.flush()
    db.session.commit()


###############################################################################
# WebApp

webapp = Flask("Marathi Samaasa Annotation", static_folder="static")
webapp.config["DEBUG"] = True
webapp.url_map.strict_slashes = False

# generate a nice key using secrets.token_urlsafe()
webapp.config["SECRET_KEY"] = config.SECRET_KEY
webapp.config["JSON_AS_ASCII"] = False
webapp.config["JSON_SORT_KEYS"] = False

# SQLAlchemy Config
webapp.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
webapp.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URI
webapp.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}

# Flask Admin Theme
webapp.config["FLASK_ADMIN_SWATCH"] = "united"

# CSRF Token Expiry
webapp.config["WTF_CSRF_TIME_LIMIT"] = None

# Custom
webapp.config["HASH_SALT"] = config.HASH_SALT

###############################################################################


class BaseModelView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    can_export = True
    create_modal = True
    edit_modal = True

    def is_accessible(self):
        authorized_users = config.ADMIN_USERS
        return (
            current_user.is_authenticated
            and current_user.username in authorized_users
        )

    def inaccessible_callback(self, name, **kwargs):
        flash("Unauthorized accesss.")
        return redirect(url_for("show_corpus", next=request.url))


class LabelModelView(BaseModelView):
    can_delete = False
    column_editable_list = ["short", "label"]


class SentenceModelView(BaseModelView):
    column_searchable_list = ["headword", "text"]


class AnnotationModelView(BaseModelView):
    can_create = False
    can_edit = False
    can_view_details = True
    column_list = [
        "annotator.username",
        "sentence.headword",
        "sentence.text",
        "label.label",
        "comment",
    ]
    column_searchable_list = [
        "annotator.username",
        "sentence.headword",
        "sentence.text",
        "label.label",
        "comment",
    ]


###############################################################################

# flask-sqlalchemy
db.init_app(webapp)

# flask-login
login_manager = LoginManager()
login_manager.init_app(webapp)

# flask-wtf
csrf = CSRFProtect(webapp)

# flask-admin
admin = Admin(webapp, name="Marāṭhi Annotation", template_mode="bootstrap4")
admin.add_view(BaseModelView(User, db.session))
admin.add_view(LabelModelView(Label, db.session))
admin.add_view(SentenceModelView(Sentence, db.session))
admin.add_view(AnnotationModelView(Annotation, db.session))

###############################################################################


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for("login"))


###############################################################################


def user_exists(username):
    return User.query.filter_by(username=username).one_or_none() is not None


def validate_user(username, password):
    return User.query.filter_by(
        username=username, hash=compute_user_hash(username, password)
    ).one_or_none()


def compute_user_hash(username, password):
    salt = webapp.config["HASH_SALT"]
    user_md5 = md5(f"{salt}.{username}.{password}".encode())
    return user_md5.hexdigest()


def create_user(username, password):
    user_hash = compute_user_hash(username, password)
    if not user_exists(username):
        user = User(username=username, hash=user_hash)
        db.session.add(user)
        db.session.commit()
        return user


###############################################################################


@webapp.before_first_request
def init_database():
    """Initiate database and create admin user"""
    db.create_all()
    admin_username = "admin"
    admin_password = "marathi"
    create_user(admin_username, admin_password)

    if not Sentence.query.count():
        import_data()

    if not Label.query.count():
        db.session.add_all(
            [Label(short=k, label=v) for k, v in config.DEFAULT_LABELS.items()]
        )
        db.session.commit()


###############################################################################
# Global Context


@webapp.context_processor
def inject_global_constants():
    return {
        "title": "Marāṭhī Samāsa",
        "now": datetime.datetime.utcnow(),
    }


###############################################################################
# Views


@webapp.route("/api", methods=["POST"])
@login_required
def api():
    api_response = {}
    api_response["success"] = False
    action = request.form.get("action")
    if action == "save_annotation":
        sentence_id = request.form.get("sentence_id")
        label_id = request.form.get("label_id")
        comment = request.form.get("comment")
        annotator_id = current_user.id
        annotation = Annotation.query.filter_by(
            sentence_id=sentence_id, annotator_id=annotator_id,
        ).one_or_none()
        if annotation is None:
            annotation = Annotation(
                sentence_id=sentence_id,
                annotator_id=annotator_id,
                label_id=label_id,
                comment=comment,
            )
        else:
            annotation.label_id = label_id
            annotation.comment = comment
        db.session.add(annotation)
        db.session.commit()
        api_response["success"] = True
        return jsonify(api_response)

    return jsonify(api_response)


@webapp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("show_corpus"))

    data = {}
    data["mode"] = "login"
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if user_exists(username):
            user = validate_user(username, password)
            if user is not None:
                login_user(user)
                flash("Logged in successfully.", "success")
                return redirect(url_for("show_corpus"))
            else:
                flash("Login failed.", "danger")
        else:
            flash("User does not exist.")
            return redirect(url_for("register"))
    return render_template("login.html", data=data)


@webapp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("show_corpus"))

    data = {}
    data["mode"] = "register"
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if user_exists(username):
            flash("User already exists.")
            return url_for("login")
        else:
            if password != confirm_password:
                flash("Passwords don't match.")
                return redirect(url_for("register"))

            user = create_user(username, password)
            login_user(user)
            flash("User created and logged in successfully.", "success")
            return redirect(url_for("show_corpus"))

    return render_template("login.html", data=data)


@webapp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


###############################################################################


@webapp.route("/", methods=["GET", "POST"])
@login_required
def show_corpus():
    data = {}
    data["sentences"] = [
        (row.id, row.headword, row.text) for row in Sentence.query.all()
    ]

    data["annotations"] = {
        annotation.sentence_id: annotation.label.label
        for annotation in Annotation.query.filter_by(
            annotator_id=current_user.id
        ).all()
    }
    if data["sentences"]:
        data["active_id"] = [
            sentence[0]
            for sentence in data["sentences"]
            if sentence[0] not in data["annotations"]
        ][0]

    data["options"] = [
        (row.id, row.short, row.label) for row in Label.query.all()
    ]

    return render_template("index.html", data=data)


###############################################################################


if __name__ == "__main__":
    host = "0.0.0.0"
    port = "2903"

    webapp.run(host=host, port=port, debug=True)
