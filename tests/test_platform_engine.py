from tests.conftest import csrf, expected_flag, login
from app.db import get_db
from app.lab import DIFFICULTY_POINTS, HINT_COST


def test_flags_are_user_specific(app):
    student = expected_flag(app, "LL18", "student")
    alice = expected_flag(app, "LL18", "alice")
    assert student != alice
    assert student.startswith("FLAG{LL18_")


def test_cross_user_flag_is_rejected(app, client):
    login(client, "student")
    token = csrf(client)
    wrong = expected_flag(app, "LL18", "alice")
    r = client.post("/lab/submit", data={"challenge_id": "LL18", "flag": wrong, "csrf_token": token}, follow_redirects=True)
    assert b"Flag rejected" in r.data
    with app.app_context():
        count = get_db().execute("SELECT COUNT(*) AS c FROM challenge_progress WHERE challenge_id='LL18'").fetchone()["c"]
        assert count == 0


def test_progress_is_persistent_server_side(app, client):
    login(client, "student")
    token = csrf(client)
    expected = expected_flag(app, "LL18", "student")
    r = client.post("/lab/submit", data={"challenge_id": "LL18", "flag": expected, "csrf_token": token}, follow_redirects=True)
    assert b"LL18 solved for" in r.data
    with client.session_transaction() as sess:
        assert "solved" not in sess
    progress = client.get("/lab/progress").get_json()
    assert progress["solved"] == 1
    assert progress["score"] == DIFFICULTY_POINTS["Beginner"]


def test_hint_reduces_awarded_score(app, client):
    login(client, "student")
    token = csrf(client)
    client.post("/lab/hint/LL19", data={"csrf_token": token}, follow_redirects=True)
    expected = expected_flag(app, "LL19", "student")
    token = csrf(client)
    client.post("/lab/submit", data={"challenge_id": "LL19", "flag": expected, "csrf_token": token}, follow_redirects=True)
    with app.app_context():
        row = get_db().execute("SELECT points_awarded FROM challenge_progress WHERE user_id=(SELECT id FROM users WHERE username='student') AND challenge_id='LL19'").fetchone()
        assert row["points_awarded"] == DIFFICULTY_POINTS["Intermediate"] - HINT_COST
