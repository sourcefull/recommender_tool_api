import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import DomainProfile
from api.recommender.serializers import domain_profile
from api.restplus import api

from database import db

from api.recommender.business import create_domain_profile, update_domain_profile, delete_domain_profile



log = logging.getLogger(__name__)

ns = api.namespace('domain_profiles', description='Domain Profile related operations')


@ns.route('/')
class DomainList(Resource):

    @api.doc('list_domain_profiles')
    @api.marshal_list_with(domain_profile)
    def get(self):
        '''
        List all domain profiles.
        Use this method to list all the existing domain profiles
        '''

        domain_profiles = DomainProfile.query.all()
        return domain_profiles

    @api.response(201, 'Domain Profile successfully created.')
    @api.expect(domain_profile)
    def post(self):

        """
        creates a domain profile
        *Send a JSON object with GBU and CVSS metric ratings
        ```
        {
            "GBU_ID": GBU ID
            "CONFIDENTIALITY_IMPACT": "Rating for Confidentiality Impact"
            "INTEGRITY_IMPACT": "Rating for Integrity Impact"
            "AVAILABILITY_IMPACT": "Rating for Availability Impact"
            "PRIVILEGES_REQUIRED": "Rating for privileges required"
            "USER_INTERACTION": "Rating for user interaction"
            "SCOPE": "Rating for scope"
            "ATTACK_COMPLEXITY": "Rating for attack complexity"
            "ACCESS_VECTOR": "rating for access vector"

        }
        ```
        """
        data = request.json
        create_domain_profile(data)

        return None, 201



@ns.route('/<int:id>')
@api.response(404, 'Domain Profile not found.')
class DomainItem(Resource):

    @api.doc('get domain profile')
    @api.marshal_with(domain_profile)
    def get(self, id):

        '''
        Returns a domain profile detail
        Given the domain profile id, returns the domain profile details
        '''



        return DomainProfile.query.filter(DomainProfile.DOMAIN_PROFILE_ID==id).one()



    @api.doc('update a domain_profile')
    @api.expect(domain_profile)
    @api.response(204, 'Domain Profile successfully updated.')
    def put(self, id):
        """
        Updates a Domain Profile.
        Use this method to change the fields of a domain profile.

        * Send a JSON object with the new fields in the request body.
        ```
        {
            "GBU_ID": GBU ID
            "CONFIDENTIALITY_IMPACT": "New Rating for Confidentiality Impact"
            "INTEGRITY_IMPACT": "New Rating for Integrity Impact"
            "AVAILABILITY_IMPACT": "New Rating for Availability Impact"
            "PRIVILEGES_REQUIRED": "New Rating for privileges required"
            "USER_INTERACTION": "New Rating for user interaction"
            "SCOPE": "New Rating for scope"
            "ATTACK_COMPLEXITY": "New Rating for attack complexity"
            "ACCESS_VECTOR": "New rating for access vector"

        }
        ```

        * specify the ID of the domain profile to modify in the request URL path.
        """

        data = request.json
        update_domain_profile(id, data)
        return None, 204

    @api.response(204, 'Domain Profile successfully deleted. ')
    def delete(self, id):
        """

        Deletes a Domain Profile

        """

        delete_domain_profile(id)





