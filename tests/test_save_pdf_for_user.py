import io
import os
from werkzeug.datastructures import FileStorage
import app


def test_save_pdf_for_user(tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    rel_path = app.save_pdf_for_user("19900101-1234", file_storage)

    abs_path = os.path.abspath(os.path.join(app.APP_ROOT, rel_path))
    assert os.path.exists(abs_path)
    with open(abs_path, "rb") as f:
        assert f.read() == pdf_bytes
