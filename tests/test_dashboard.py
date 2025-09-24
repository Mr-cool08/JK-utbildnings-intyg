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
                    "category": "Utbildning",
                    "content": b"%PDF-1.4 own",
                },
                {
                    "personnummer": other_hash,
                    "filename": "other.pdf",
                    "category": "Annat",
                    "content": b"%PDF-1.4 other",
                },
            ],
        )

    with app.app.test_client() as client:
        client.post("/login", data={"personnummer": "9001011234", "password": "secret"})
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data
        assert "Kategori: Utbildning".encode() in response.data


def test_dashboard_category_filter(user_db):
    engine = user_db
    pnr_hash = functions.hash_value("9001011234")

    with engine.begin() as conn:
        conn.execute(
            functions.user_pdfs_table.insert(),
            [
                {
                    "personnummer": pnr_hash,
                    "filename": "first.pdf",
                    "category": "Kurs",
                    "content": b"%PDF-1.4 first",
                },
                {
                    "personnummer": pnr_hash,
                    "filename": "second.pdf",
                    "category": "Intyg",
                    "content": b"%PDF-1.4 second",
                },
            ],
        )

    with app.app.test_client() as client:
        client.post("/login", data={"personnummer": "9001011234", "password": "secret"})
        response = client.get("/dashboard", query_string={"kategori": "Intyg"})
        assert b"second.pdf" in response.data
        assert b"first.pdf" not in response.data
        assert b'value="Intyg" selected' in response.data
