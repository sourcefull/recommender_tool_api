import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import UserProfile
from api.recommender.serializers import user_profile
from api.restplus import api

from database import db

from api.recommender.business import create_user_profile, update_user_profile, delete_user_profile



log = logging.getLogger(__name__)

ns = api.namespace('user_profiles', description='User Profile related operations')


@ns.route('/')
class UserList(Resource):

    @api.doc('list user profiles')
    @api.marshal_list_with(user_profile)
    def get(self):
        '''
        List all user profiles.
        Use this method to list all the existing user profiles
        '''

        user_profiles = UserProfile.query.all()
        return user_profiles

    @api.response(201, 'User Profile successfully created.')
    @api.expect(user_profile)
    def post(self):

        """
        creates a user profile
        *Send a JSON object with GBU and CVSS metric ratings
        ```
        {
            "DOMAIN_PROFILE_ID": domain profile id
            "SERVICE_ID": service id
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
        create_user_profile(data)

        return None, 201



@ns.route('/<int:id>')
@api.response(404, 'User Profile not found.')
class UserItem(Resource):

    @api.doc('get user profile')
    @api.marshal_with(user_profile)
    def get(self, id):

        '''
        Returns a user profile detail
        Given the user profile id, returns the user profile details
        '''



        return UserProfile.query.filter(UserProfile.USER_PROFILE_ID==id).one()



    @api.doc('update a user_profile')
    @api.expect(user_profile)
    @api.response(204, 'User Profile successfully updated.')
    def put(self, id):
        """
        Updates a User Profile.
        Use this method to change the fields of a User profile.

        * Send a JSON object with the new fields in the request body.
        ```
        {
            "DOMAIN_PROFILE_ID": "domain profile id"
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

        * specify the ID of the user profile to modify in the request URL path.
        """

        data = request.json
        update_user_profile(id, data)
        return None, 204

    @api.response(204, 'User Profile successfully deleted. ')
    def delete(self, id):
        """

        Deletes a User Profile

        """

        delete_user_profile(id)


