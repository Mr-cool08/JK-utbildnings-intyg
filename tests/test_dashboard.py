# Copyright (c) Liam Suorsa and Mika Suorsa
import app
import functions
from course_categories import COURSE_CATEGORIES


def test_dashboard_shows_only_user_pdfs(user_db):
    engine = user_db
    own_hash = functions.hash_value("9001011234")
    other_hash = functions.hash_value("0001011234")

    with engine.begin() as conn:
        conn.execute(
            functions.user_pdfs_table.insert(),
            [
                {
                    "personnummer": own_hash,
                    "filename": "own.pdf",
                    "content": b"%PDF-1.4 own",
                    "categories": COURSE_CATEGORIES[0][0],
                },
                {
                    "personnummer": other_hash,
                    "filename": "other.pdf",
                    "content": b"%PDF-1.4 other",
                    "categories": COURSE_CATEGORIES[1][0],
                },
            ],
        )

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data
        assert COURSE_CATEGORIES[0][1].encode() in response.data
