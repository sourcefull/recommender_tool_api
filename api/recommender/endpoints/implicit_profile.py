import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import ImplicitProfile
from api.recommender.serializers import implicit_profile
from api.restplus import api

from database import db
from api.recommender.business import update_implicit_profile

log = logging.getLogger(__name__)

ns = api.namespace('implicit_profiles', description='Implicit Profile related operations')


@ns.route('/')
class ImplicitList(Resource):

    @api.doc('list implicit profiles')
    @api.marshal_list_with(implicit_profile)
    def get(self):
        '''
        List all implicit profiles.
        Use this method to list all the existing implicit profiles
        '''

        implicit_profiles = ImplicitProfile.query.all()
        return implicit_profiles


'''
@ns.route('/<int:id>/<string:cve>', methods = ['PUT'])
@api.response(404, 'cve or implicit profile not found.')
class updateImplicit(Resource):

    @api.doc('update through implicit feedback')
    @api.expect(implicit_profile)
    @api.response(204, 'Implicit Profile successfully updated.')
    def put(self, id, cve):
        data = request.json
        mer_implicit(id, data, cve)
        return None, 204
    
'''



@ns.route('/<int:id>')
@api.response(404, 'Implicit Profile not found.')
class ImplicitItem(Resource):

    @api.doc('get implicit profile')
    @api.marshal_with(implicit_profile)
    def get(self, id):
        '''
        Returns a implicit profile detail
        Given the implicit profile id, returns the implicit profile details
        '''

        return ImplicitProfile.query.filter(ImplicitProfile.IMPLICIT_PROFILE_ID==id).one()




    @api.doc('update through implicit feedback')
    @api.expect(implicit_profile)
    @api.response(204, 'Implicit Profile successfully updated.')
    def put(self, id):
        """
        Updates an Implicit Profile
        Use this method to change the fields of an implicit profile through the merge algorithm

        * Send a JSON object with the CVE ID in the request body to update implicit profile.
        ```
        {
            "CVE": "CVE ID"

        }
        ```

        * specify the ID of the implicit profile to modify in the request URL path.
        """

        data = request.json
        update_implicit_profile(id, data)
        return None, 204




