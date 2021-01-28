import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import GBUs
from api.recommender.serializers import gbu, gbu_with_services
from api.restplus import api
from database import db
from api.recommender.business import update_gbu, delete_gbu, create_gbu


log = logging.getLogger(__name__)

ns = api.namespace('gbus', description='GBU related operations')



@ns.route('/')
class GbuList(Resource):

    @api.doc('list gbus')
    @api.marshal_list_with(gbu)
    def get(self):
        '''
        List all gbus.
        Use this method to list all the existing gbus.

        '''
        gbus = GBUs.query.all()
        return gbus

    @api.response(201, 'GBU successfully created.')
    @api.expect(gbu)
    def post(self):
        """
        creates a gbu
        * Send a JSON object with GBU name in the request body
         ```
        {
            "GBU": "GBU name"
        }
        ```

        """

        data = request.json

        create_gbu(data)


        return None, 201



@ns.route('/<int:id>')
@api.response(404, 'GBU not found.')
class GbuItem(Resource):

    @api.doc('get gbu')
    @api.marshal_with(gbu_with_services)
    def get(self, id):

        '''Returns a gbu'''

        return GBUs.query.filter(GBUs.GBU_ID == id).one()


    @api.doc('update a gbu')
    @api.expect(gbu)
    @api.response(204, 'GBU successfully updated.')
    def put(self, id):
        """
        Updates a GBU.
        Use this method to change the name of a GBU.

        * Send a JSON object with the new name in the request body.
        ```
        {
            "GBU": "New GBU name"
        }
        ```

        * specify the ID of the gbu to modify in the request URL path.
        """

        data = request.json
        update_gbu(id, data)
        return None, 204

    @api.response(204, 'GBU successfully deleted. ')
    def delete(self, id):
        """

        Deletes a gbu

        """

        delete_gbu(id)
        return None, 204