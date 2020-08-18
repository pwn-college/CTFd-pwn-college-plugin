import os
import struct
import hmac
import hashlib

from flask import current_app

from .settings import INSTANCE


def user_flag(account_id, challenge_id, secret=None):
    if secret is None:
        secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode("latin")
    prefix = f"{INSTANCE}_".encode()
    data = struct.pack("ll", account_id, challenge_id)
    return hmac.new(prefix + secret, data, hashlib.sha1).hexdigest()


def challenge_path(account_id, category, challenge):
    account_id = str(account_id)

    def is_safe(segment):
        return segment != "." and segment != ".." and "/" not in segment

    if not is_safe(account_id) or not is_safe(category) or not is_safe(challenge):
        return None

    paths = [
        os.path.join("/", "challenges", account_id, category, challenge),
        os.path.join("/", "challenges", "global", category, challenge),
    ]

    for path in paths:
        if os.path.isfile(path):
            return path
