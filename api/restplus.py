from flask_restx import Api

import logging
import traceback

import settings
from sqlalchemy.orm.exc import NoResultFound
log = logging.getLogger(__name__)

api = Api(
    title='Recommender-tool',
    version='1.0',
    description='API for recommender tool that calculates the Oracle Severity Score based on the domain and user profile',
    # All API metadatas
)


@api.errorhandler
def default_error_handler(e):
    message = 'An unhandled exception occurred.'
    log.exception(message)

    if not settings.FLASK_DEBUG:
        return {'message': message}, 500


@api.errorhandler(NoResultFound)
def database_not_found_error_handler(e):
    log.warning(traceback.format_exc())
    return {'message': 'A database result was required but none was found.'}, 404



