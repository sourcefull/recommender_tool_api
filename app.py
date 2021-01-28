import logging.config

import os
from flask import Flask, Blueprint
import settings
from api.recommender.endpoints.services import ns as service_namespace
from api.recommender.endpoints.domain_profile import ns as domain_profile_namespace
from api.recommender.endpoints.implicit_profile import ns as implicit_profile_namespace
from api.recommender.endpoints.user_profile import ns as user_profile_namespace
from api.recommender.endpoints.gbu import ns as gbu_namespace
from api.recommender.endpoints.vul_record import ns as vul_record_namespace
from api.recommender.endpoints.vulnerabilities import ns as vulnerabilities_namespace
from api.recommender.endpoints.oracle_severity_score import ns as oracle_severity_score_namespace
from api.restplus import api
from database import db, db_seed

app = Flask(__name__)
logging_conf_path = os.path.normpath(os.path.join(os.path.dirname(__file__), 'logging.conf'))
logging.config.fileConfig(logging_conf_path)
log = logging.getLogger(__name__)


def configure_app(flask_app):
    flask_app.config['SERVER_NAME'] = settings.FLASK_SERVER_NAME
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = settings.SQLALCHEMY_DATABASE_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = settings.SQLALCHEMY_TRACK_MODIFICATIONS
    flask_app.config['SWAGGER_UI_DOC_EXPANSION'] = settings.RESTPLUS_SWAGGER_UI_DOC_EXPANSION
    flask_app.config['RESTPLUS_VALIDATE'] = settings.RESTPLUS_VALIDATE
    flask_app.config['RESTPLUS_MASK_SWAGGER'] = settings.RESTPLUS_MASK_SWAGGER
    flask_app.config['ERROR_404_HELP'] = settings.RESTPLUS_ERROR_404_HELP


def initialize_app(flask_app):
    configure_app(flask_app)

    blueprint = Blueprint('api', __name__, url_prefix='/api')
    api.init_app(blueprint)
    api.add_namespace(service_namespace)
    api.add_namespace(user_profile_namespace)
    api.add_namespace(domain_profile_namespace)
    api.add_namespace(implicit_profile_namespace)
    api.add_namespace(gbu_namespace)
    api.add_namespace(vul_record_namespace)
    api.add_namespace(vulnerabilities_namespace)
    api.add_namespace(oracle_severity_score_namespace)
    flask_app.register_blueprint(blueprint)

    with flask_app.test_request_context():
        db.init_app(app)
        db.drop_all()
        db.create_all()
        db_seed()




def main():
    initialize_app(app)
    log.info('>>>>> Starting development server at http://{}/api/ <<<<<'.format(app.config['SERVER_NAME']))
    #reset_database()
    app.run(debug=settings.FLASK_DEBUG)



if __name__ == "__main__":

    main()



