import os
import base64
import json

from flask import request, Blueprint, abort, send_file
from flask_restx import Namespace, Resource
from CTFd.utils.user import get_current_user
from CTFd.utils.decorators import authed_only
from CTFd.utils.security.signing import serialize, unserialize

from .settings import INSTANCE
from .utils import challenge_path
from .docker_challenge import DockerChallenges


download = Blueprint("download", __name__)


@download.route("/download/<token>")
def download_challenge(token):
    try:
        data = unserialize(token)
        unauthed = True
    except:
        try:
            data = json.loads(base64.b64decode(token))
            unauthed = False
        except:
            abort(404)

    try:
        if unauthed:
            account_id = int(data["account_id"])
        else:
            user = get_current_user()
            account_id = user.account_id

        challenge_id = int(data["challenge_id"])
        challenge = DockerChallenges.query.filter_by(id=challenge_id).first()

        category = challenge.category
        challenge = challenge.name

    except:
        abort(404)

    chall_path = challenge_path(account_id, category, challenge)
    if not chall_path:
        abort(404)

    filename = f"{category}_{challenge}"

    return send_file(
        chall_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        attachment_filename=filename,
    )


download_namespace = Namespace("download", description="Endpoint to manage downloads")


@download_namespace.route("/generate")
class GenerateDownload(Resource):
    @authed_only
    def get(self):
        data = request.get_json()
        challenge_id = data.get("challenge_id")

        try:
            challenge_id = int(challenge_id)
        except (ValueError, TypeError):
            return {"success": False, "error": "Invalid challenge id"}

        challenge = DockerChallenges.query.filter_by(id=challenge_id).first()
        if not challenge:
            return {"success": False, "error": "Invalid challenge"}

        user = get_current_user()
        account_id = user.account_id

        token = serialize({"account_id": account_id, "challenge_id": challenge_id})

        return {
            "success": True,
            "url": f"https://{INSTANCE}.pwn.college/download/{token}",
        }
