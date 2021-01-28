import logging
from flask import jsonify
from flask_restx import Resource
from api.restplus import api
from machine_learning.ml_algorithms import calculate_score

log = logging.getLogger(__name__)

ns = api.namespace('get_oracleseverityscore', description='calculate oracle severity score')


@ns.route('/<int:gbu_id>/<int:service_id>/<string:cve>')
@api.response(404, 'Could not calculate score')
class Oracle_Severity_Score(Resource):

    @api.doc('calculate oracle severity score')
    #@api.marshal_list_with(vul_record)
    @api.response(200, 'Oracle score successfully calculated.')
    def get(self,gbu_id,service_id,cve):
        '''
        Use this method to calculate oracle severity score
        '''


        final_score = calculate_score(gbu_id, service_id, cve)

        return jsonify(message = "oracle severity score is {}".format(final_score))
