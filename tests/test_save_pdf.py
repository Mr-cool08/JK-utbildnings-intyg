import io
import os
import sys
# ensure project root is on sys.path so we import the local main.py
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
from main import save_pdf_for_user, APP_ROOT

class FakeFileStorage:
    def __init__(self, filename, content=b"%PDF- fake pdf content\n"):
        self.filename = filename
        self.stream = io.BytesIO(content)
        self.mimetype = 'application/pdf'
    def save(self, path):
        # ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(self.stream.getvalue())


def run_test():
    pnr = '199001011234'
    # filename that contains the personnummer
    fake = FakeFileStorage('199001011234_resume.pdf')
    rel = save_pdf_for_user(pnr, fake)
    print('Saved relative path:', rel)
    abs_path = os.path.join(APP_ROOT, rel)
    print('File exists:', os.path.exists(abs_path))
    print('Filename contains pnr?', str(pnr) in os.path.basename(abs_path))

if __name__ == '__main__':
    run_test()
