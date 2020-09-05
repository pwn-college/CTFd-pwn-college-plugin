import os
import sys
import pathlib
import tempfile
import tarfile

import docker
import requests
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

from .settings import INSTANCE, HOST_DATA_PATH, VIRTUAL_HOST
from .utils import serialize_user_flag, challenge_path


class DockerChallenges(Challenges):
    __mapper_args__ = {"polymorphic_identity": "docker"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    docker_image_name = db.Column(db.String(32))


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

    def get_challenge(self, user, challenge_id):
        try:
            challenge_id = int(challenge_id)
        except (ValueError, TypeError):
            return None, "Invalid challenge id"

        challenge = DockerChallenges.query.filter_by(id=challenge_id).first()
        if not challenge:
            return None, "Invalid challenge"

        chall_path = challenge_path(user.id, challenge.category, challenge.name)
        if not chall_path:
            print(
                f"Challenge data does not exist: {user.id}, {challenge.category}, {challenge.name}",
                file=sys.stderr,
                flush=True,
            )
            return None, "Challenge data does not exist"

        return challenge, None

    def kill_user_container(self, user):
        docker_client = docker.from_env()
        container_name = f"{INSTANCE}_user_{user.id}"
        try:
            container = docker_client.containers.get(container_name)
            container.kill()
            container.wait(condition="removed")
        except docker.errors.NotFound:
            pass

    def kill_container(self, container):
        try:
            container.kill()
            container.wait(condition="removed")
        except docker.errors.NotFound:
            pass

    def init_user_container(self, user, challenge):
        docker_client = docker.from_env()
        image_name = challenge.docker_image_name
        category = challenge.category
        challenge_id = challenge.id
        challenge_name = challenge.name
        container_name = f"{INSTANCE}_user_{user.id}"

        try:
            container = docker_client.containers.run(
                image_name,
                ["/bin/bash", "-c", "while true; do su ctf; done"],
                name=container_name,
                hostname=f"{category}_{challenge_name}",
                environment={"CHALLENGE_ID": str(challenge_id)},
                mounts=[
                    docker.types.Mount(
                        "/home/ctf",
                        f"{HOST_DATA_PATH}/homes/nosuid/{user.id}",
                        "bind",
                        propagation="shared",
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
            return container
        except Exception as e:
            print(f"Docker failed: {e}", file=sys.stderr, flush=True)
            return None

    def check_mount(self, user, container):
        """ make sure /home/ctf is mounted and mounted as nosuid """
        exit_code, output = container.exec_run("findmnt --output OPTIONS /home/ctf")
        if exit_code != 0:
            self.kill_container(container)
            print(
                f"Home directory failed to mount for user {user.id}",
                file=sys.stderr,
                flush=True,
            )
            return "Home directory failed to mount"
        elif b"nosuid" not in output:
            self.kill_container(container)
            print(
                f"Home directory failed to mount as nosuid for user {user.id}",
                file=sys.stderr,
                flush=True,
            )
            return "Home directory failed to mount as nosuid"
        return None

    def inject_suid(self, user, container, challenge):
        challenge_name = challenge.name
        category = challenge.category
        account_id = user.account_id

        chall_path = challenge_path(account_id, category, challenge_name)
        def simple_tar(path, name=None):
            f = tempfile.NamedTemporaryFile()
            t = tarfile.open(mode="w", fileobj=f)

            abs_path = os.path.abspath(path)
            t.add(
                abs_path, arcname=(name or os.path.basename(path)), recursive=False
            )

            t.close()
            f.seek(0)
            return f

        with simple_tar(chall_path, f"{category}_{challenge_name}") as tar:
            container.put_archive("/", tar)

        suid_path = f"/{category}_{challenge_name}"

        container.exec_run(
            f"""/bin/sh -c \"
            chmod 4755 {suid_path};
            touch /flag;
            chmod 400 /flag;
            \""""
        )

    def enable_sudo(self, container, challenge):
        category = challenge.category
        challenge_name = challenge.name
        container.exec_run(
            f"""/bin/sh -c \"
            chmod 4755 /usr/bin/sudo;
            adduser ctf sudo;
            echo 'ctf ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers;
            echo '127.0.0.1\t{category}_{challenge_name}' >> /etc/hosts;
            \""""
        )

    def inject_flag(self, container, flag):
        flag = f"pwn_college{{{flag}}}"
        container.exec_run(f"/bin/sh -c \"echo '{flag}' > /flag\"")

    @authed_only
    def post(self):
        data = request.get_json()
        challenge_id = data.get("challenge_id")
        practice = data.get("practice")
        user = get_current_user()
        account_id = user.account_id

        challenge, error_msg = self.get_challenge(user, challenge_id)
        if error_msg or not challenge:
            return {"success": False, "error": error_msg}

        # kill existing user container and restart a new one based on the challenge
        self.kill_user_container(user)
        container = self.init_user_container(user, challenge)
        if not container:
            return {"success": False, "error": "Docker failed"}

        # try:
        #     response = requests.post(f"http://home_daemon/init/{user.id}").json()
        #     if not response["success"]:
        #         error = response["error"]
        #         print(
        #             f"Home daemon failed to init home for user {user.id}: {error}",
        #             file=sys.stderr,
        #             flush=True,
        #         )
        #         return {"success": False, "error": "Home daemon failed to init home"}
        # except Exception as e:
        #     print(f"Failed to reach home daemon: {e}", file=sys.stderr, flush=True)
        #     return {"success": False, "error": "Failed to reach home daemon"}

        error_msg = self.check_mount(user, container)
        if error_msg:
            return {"success": False, "error": error_msg}

        extra_data = None

        # inject suid binary or make a binary suid in a hacky way
        if challenge.category == "babysuid":
            # TODO: make babysuid not so hacked in
            selected_path = data.get("selected_path")

            # No command injection please
            selected_path = selected_path.replace("'", "").replace('"', "")

            exit_code, output = container.exec_run(
                f"""/bin/sh -c \"
                test -f '{selected_path}' &&
                chmod u+s '{selected_path}' &&
                readlink -e '{selected_path}';
                \""""
            )

            if exit_code != 0:
                self.kill_container(container)
                return {"success": False, "error": "Invalid path"}

            selected_path = output.decode("latin").strip()

            extra_data = selected_path

        else:
            self.inject_suid(user, container, challenge)

        # prepare flag string
        if not practice:
            flag = serialize_user_flag(account_id, challenge_id, extra_data)
        else:
            self.enable_sudo(container, challenge)
            flag = serialize_user_flag(0, 0, 0)

        # inject it into container
        self.inject_flag(container, flag)

        return {"success": True, "ssh": f"ssh {INSTANCE}@{VIRTUAL_HOST}"}

    @authed_only
    def get(self):
        user = get_current_user()
        docker_client = docker.from_env()
        container_name = f"{INSTANCE}_user_{user.id}"

        # get container by name
        try:
            container = docker_client.containers.get(container_name)
        except docker.errors.NotFound:
            return {"success": False, "error": "No container"}

        # make sure the container has CHALLENGE_ID environment variable
        for env in container.attrs["Config"]["Env"]:
            if env.startswith("CHALLENGE_ID"):
                break
        else:
            return {"success": False, "error": "No challenge id"}

        # make sure the variable is a valid CHALLENGE_ID
        try:
            challenge_id = int(env[len("CHALLENGE_ID=") :])
            return {"success": True, "challenge_id": challenge_id}
        except ValueError:
            return {"success": False, "error": "Invalid challenge id"}
