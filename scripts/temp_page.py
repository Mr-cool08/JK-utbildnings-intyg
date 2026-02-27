def tempwebsite():
    import flask

    def create_app():
        app = flask.Flask(__name__)
        return app

    app = create_app()



    @app.route("/")
    def hello():
        return "The website is updating please wait a moment and refresh the page."
    
    
    app.run(debug=True, port=80)