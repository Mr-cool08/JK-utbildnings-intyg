from werkzeug.middleware.proxy_fix import ProxyFix
from main import create_app

app = create_app()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

if __name__ == "__main__":
    app.run()
