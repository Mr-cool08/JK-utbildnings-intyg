import app
import functions


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
                },
                {
                    "personnummer": other_hash,
                    "filename": "other.pdf",
                    "content": b"%PDF-1.4 other",
                },
            ],
        )

    with app.app.test_client() as client:
        client.post("/login", data={"personnummer": "9001011234", "password": "secret"})
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data
