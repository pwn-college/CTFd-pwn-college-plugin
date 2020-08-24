import os

from flask import Blueprint, current_app
from flask_restx import Api
from CTFd.models import db
from CTFd.forms import Forms
from CTFd.utils import get_config
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user
from CTFd.utils.plugins import register_script, override_template
from CTFd.plugins import register_plugin_assets_directory, register_user_page_menu_bar
from CTFd.plugins.challenges import CHALLENGE_CLASSES
from CTFd.plugins.flags import FLAG_CLASSES

from .docker_challenge import DockerChallenge, docker_namespace
from .user_flag import UserFlag, CheaterUserFlag
from .ssh_key import Keys, KeyForm, key_settings, keys_namespace
from .download import download, download_namespace
from .terminal import terminal
from .binary_ninja import binary_ninja_namespace
from .grades import grades


def load(app):
    dir_path = os.path.dirname(os.path.realpath(__file__))

    db.create_all()

    register_plugin_assets_directory(
        app, base_path="/plugins/CTFd-pwn-college-plugin/assets/"
    )

    CHALLENGE_CLASSES["docker"] = DockerChallenge

    FLAG_CLASSES["user"] = UserFlag
    FLAG_CLASSES["cheater"] = CheaterUserFlag

    key_template_path = os.path.join(dir_path, "assets", "key", "settings.html")
    override_template("settings.html", open(key_template_path).read())
    app.view_functions["views.settings"] = key_settings
    Forms.keys = {"KeyForm": KeyForm}

    blueprint = Blueprint("pwncollege_api", __name__)
    api = Api(blueprint, version="v1", doc=current_app.config.get("SWAGGER_UI"))
    api.add_namespace(keys_namespace, "/key")
    api.add_namespace(docker_namespace, "/docker")
    api.add_namespace(download_namespace, "/download")
    api.add_namespace(binary_ninja_namespace, "/binary_ninja")
    app.register_blueprint(blueprint, url_prefix="/pwncollege_api/v1")

    app.register_blueprint(download)

    app.register_blueprint(terminal)
    register_user_page_menu_bar("Terminal", "/terminal")

    app.register_blueprint(grades)
    register_user_page_menu_bar("Grades", "/grades")
