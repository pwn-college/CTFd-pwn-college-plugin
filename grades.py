import datetime

from flask import Blueprint, render_template, request
from sqlalchemy.sql import or_
from CTFd.models import db, Challenges, Solves
from CTFd.utils.user import get_current_user, is_admin
from CTFd.utils.decorators import authed_only


grades = Blueprint("grades", __name__, template_folder="assets/grades/")

az_timezone = datetime.timezone(datetime.timedelta(hours=-7))
deadlines = {"babysuid": datetime.datetime(2020, 12, 1, tzinfo=az_timezone)}


@grades.route("/grades", methods=["GET"])
@authed_only
def view_grades():
    user_id = get_current_user().id
    if request.args.get("id") and is_admin():
        try:
            user_id = int(request.args.get("id"))
        except ValueError:
            pass

    grades = []
    available_total = 0
    solves_total = 0

    makeup_grades = []
    makeup_solves_total = 0

    challenges = (
        db.session.query(Challenges.category, db.func.count())
        .filter(Challenges.state == "visible")
        .filter(Challenges.value > 0)
        .group_by(Challenges.category)
    )
    for category, num_available in challenges:
        solves = (
            Solves.query.filter_by(user_id=user_id)
            .join(Challenges)
            .filter(Challenges.category == category)
        )
        makeup_solves = (
            Solves.query.filter_by(user_id=user_id)
            .join(Challenges)
            .filter(Challenges.category == category)
        )

        deadline = deadlines.get(category)
        if deadline:
            solves = solves.filter(Solves.date < deadline)

        num_solves = solves.count()
        makeup_num_solves = makeup_solves.count()

        available_total += num_available
        solves_total += num_solves
        makeup_solves_total += makeup_num_solves

        grades.append(
            {
                "category": category,
                "due": str(deadline or ""),
                "completed": f"{num_solves}/{num_available}",
                "grade": num_solves / num_available,
            }
        )

        makeup_grades.append(makeup_num_solves / num_available)

    max_time = datetime.datetime.max.replace(tzinfo=az_timezone)
    grades.sort(key=lambda k: (deadlines.get(k["category"], max_time), k["category"]))

    def average(data):
        data = list(data)
        if not data:
            return 0.0
        return sum(data) / len(data)

    grades.append(
        {
            "category": "makeup",
            "due": "",
            "completed": f"{makeup_solves_total}/{available_total}",
            "grade": average(makeup_grades),
        }
    )

    grades.append(
        {
            "category": "overall",
            "due": "",
            "completed": f"{solves_total}/{available_total}",
            "grade": average(g["grade"] for g in grades),
        }
    )

    for grade in grades:
        grade["grade"] = f'{grade["grade"]:.2f}%'

    return render_template("grades.html", grades=grades)
