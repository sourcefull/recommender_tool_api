import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import VulRecord
from api.recommender.serializers import vul_record
from api.restplus import api

from database import db

from api.recommender.business import create_user_profile, update_user_profile, delete_user_profile



log = logging.getLogger(__name__)

ns = api.namespace('vul_record', description='Vulnerability Record related operations')

@ns.route('/')
class Vul_RecordList(Resource):

    @api.doc('list vul record profiles')
    @api.marshal_list_with(vul_record)
    def get(self):
        '''
        List all vulnerability record.
        Use this method to list all the existing vulnerability records
        '''

        vul_records = VulRecord.query.all()
        return vul_records

