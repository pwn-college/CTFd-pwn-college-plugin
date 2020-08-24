import os
import sys
import tempfile
import tarfile

import docker

from flask import request, Blueprint
from flask_restx import Namespace, Resource
from CTFd.models import (
    db,
    Solves,
    Fails,
    Flags,
    Challenges,
    ChallengeFiles,
    Tags,
    Hints,
)
from CTFd.utils.user import get_ip, get_current_user
from CTFd.utils.decorators import authed_only
from CTFd.utils.uploads import delete_file
from CTFd.plugins.challenges import BaseChallenge
from CTFd.plugins.flags import get_flag_class

from .settings import INSTANCE, HOST_DATA_PATH
from .utils import user_flag, challenge_path


class DockerChallenges(Challenges):
    __mapper_args__ = {"polymorphic_identity": "docker"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    docker_image_name = db.Column(db.String(32))

    def __init__(self, *args, **kwargs):
        super(DockerChallenges, self).__init__(**kwargs)


class DockerChallenge(BaseChallenge):
    id = "docker"  # Unique identifier used to register challenges
    name = "docker"  # Name of a challenge type
    templates = {  # Templates used for each aspect of challenge editing & viewing
        "create": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/create.html",
        "update": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/update.html",
        "view": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/view.html",
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        "create": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/create.js",
        "update": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/update.js",
        "view": "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/view.js",
    }
    # Route at which files are accessible. This must be registered using register_plugin_assets_directory()
    route = "/plugins/CTFd-pwn-college-plugin/assets/docker_challenge/"
    # Blueprint used to access the static_folder directory.
    blueprint = Blueprint(
        "docker", __name__, template_folder="templates", static_folder="assets"
    )
    challenge_model = DockerChallenges


docker_namespace = Namespace(
    "docker", description="Endpoint to manage docker containers"
)


@docker_namespace.route("")
class RunDocker(Resource):
    @authed_only
    def post(self):
        data = request.get_json()
        challenge_id = data.get("challenge_id")
        practice = data.get("practice")

        try:
            challenge_id = int(challenge_id)
        except (ValueError, TypeError):
            return {"success": False, "error": "Invalid challenge id"}

        challenge = DockerChallenges.query.filter_by(id=challenge_id).first()

        if not challenge:
            return {"success": False, "error": "Invalid challenge"}

        user = get_current_user()
        account_id = user.account_id

        image_name = challenge.docker_image_name
        category = challenge.category
        challenge = challenge.name
        flag = user_flag(account_id, challenge_id)
        flag = f"pwn_college{{{flag}}}"

        chall_path = challenge_path(account_id, category, challenge)
        if not chall_path:
            return {"success": False, "error": "Challenge data does not exist"}

        docker_client = docker.from_env()

        container_name = f"{INSTANCE}_user_{user.id}"

        try:
            container = docker_client.containers.get(container_name)
            container.kill()
            container.wait(condition="removed")
        except docker.errors.NotFound:
            pass

        try:
            # TODO: what if we create the container, and then only start it once its configured...
            container = docker_client.containers.run(
                image_name,
                ["/bin/bash", "-c", "while true; do su ctf; done"],
                name=container_name,
                hostname=f"{category}_{challenge}",
                environment={"CHALLENGE_ID": str(challenge_id)},
                mounts=[
                    docker.types.Mount(
                        "/home/ctf", f"{HOST_DATA_PATH}/home-nosuid/{user.id}", "bind"
                    )
                ],
                network="none",
                cap_add=["SYS_PTRACE"],
                pids_limit=100,
                mem_limit="500m",
                detach=True,
                tty=True,
                stdin_open=True,
                remove=True,
            )
        except Exception as e:
            print(f"Docker failed: {e}", file=sys.stderr)
            return {"success": False, "error": "Docker failed"}

        # TODO: sanity check that "/home/ctf" is nosuid

        def simple_tar(path, name=None):
            f = tempfile.NamedTemporaryFile()
            t = tarfile.open(mode="w", fileobj=f)

            abs_path = os.path.abspath(path)
            t.add(abs_path, arcname=(name or os.path.basename(path)), recursive=False)

            t.close()
            f.seek(0)
            return f

        with simple_tar(chall_path, f"{category}_{challenge}") as tar:
            container.put_archive("/", tar)

        container.exec_run(f"chmod 4755 /{category}_{challenge}")

        if not practice:
            container.exec_run(f"/bin/sh -c \"echo '{flag}' > /flag\"")

        else:
            container.exec_run("chmod 4755 /usr/bin/sudo")
            container.exec_run("adduser ctf sudo")
            container.exec_run(
                "/bin/sh -c \"echo 'ctf ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\""
            )
            container.exec_run(
                f"/bin/sh -c \"echo '127.0.0.1\t{category}_{challenge}' >> /etc/hosts\""
            )
            empty_flag = "pwn_college{0000000000000000000000000000000000000000}"
            container.exec_run(f"/bin/sh -c \"echo '{empty_flag}' > /flag\"")

        return {"success": True, "ssh": f"ssh {INSTANCE}@{INSTANCE}.pwn.college"}

    @authed_only
    def get(self):
        user = get_current_user()

        docker_client = docker.from_env()

        container_name = f"{INSTANCE}_user_{user.id}"

        try:
            container = docker_client.containers.get(container_name)
        except docker.errors.NotFound:
            return {"success": False, "error": "No container"}

        for env in container.attrs["Config"]["Env"]:
            if env.startswith("CHALLENGE_ID"):
                try:
                    challenge_id = int(env[len("CHALLENGE_ID=") :])
                    return {"success": True, "challenge_id": challenge_id}
                except ValueError:
                    return {"success": False, "error": "Invalid challenge id"}
        else:
            return {"success": False, "error": "No challenge id"}
