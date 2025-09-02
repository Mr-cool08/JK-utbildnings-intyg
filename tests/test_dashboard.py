import app
import functions


def test_dashboard_shows_only_user_pdfs(user_db, tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    user_dir = tmp_path / functions.hash_value("199001011234")
    user_dir.mkdir()
    (user_dir / "own.pdf").write_text("test")

    other_dir = tmp_path / functions.hash_value("200001011234")
    other_dir.mkdir()
    (other_dir / "other.pdf").write_text("test")

    with app.app.test_client() as client:
        client.post("/login", data={"personnummer": "199001011234", "password": "secret"})
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data
