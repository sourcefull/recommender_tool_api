import os

basedir = os.path.abspath(os.path.dirname(__file__))


# Flask settings
FLASK_SERVER_NAME = 'localhost:8888'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False

# SQLAlchemy settings
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'recommender.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False