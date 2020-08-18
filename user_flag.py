import re
import struct
import hmac
import hashlib

from CTFd.plugins.flags import BaseFlag
from CTFd.utils.user import get_current_user

from .utils import user_flag


class UserFlag(BaseFlag):
    name = "user"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/pwncollege/assets/user_flag/create.html",
        "update": "/plugins/pwncollege/assets/user_flag/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        challenge_id = chal_key_obj.challenge_id
        account_id = get_current_user().account_id

        correct = user_flag(account_id, challenge_id)

        provided = str(provided)
        provided = re.sub(".+?{(.+)}", r"\1", provided)

        return hmac.compare_digest(correct, provided)


class CheaterUserFlag(BaseFlag):
    name = "cheater"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/pwncollege/assets/cheater_flag/create.html",
        "update": "/plugins/pwncollege/assets/cheater_flag/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        challenge_id = chal_key_obj.challenge_id
        account_id = get_current_user().account_id

        correct = user_flag(account_id, challenge_id)
        provided = re.sub(".+?{(.+)}", r"\1", provided)

        def cheater_flag(account_id):
            return user_flag(account_id, challenge_id)

        return any(hmac.compare_digest(cheater_flag(id), provided) for id in range(256))
