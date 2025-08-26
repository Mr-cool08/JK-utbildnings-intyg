from main import app as flask_app
from werkzeug.middleware.proxy_fix import ProxyFix

app = ProxyFix(flask_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

if __name__ == "__main__":
    app.run()
