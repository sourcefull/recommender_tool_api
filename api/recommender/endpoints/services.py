import logging
from flask import request, jsonify
from flask_restx import Resource, fields
from database.models import Services
from api.recommender.serializers import service, service_with_vulnerabilities
from api.restplus import api
from database import db
from api.recommender.business import update_service, delete_service, create_service


log = logging.getLogger(__name__)

ns = api.namespace('services', description='Services related operations')



@ns.route('/')
class ServiceList(Resource):

    @api.doc('list services')
    @api.marshal_list_with(service)
    def get(self):
        '''
        List all services.
        Use this method to list all the existing services.

        '''
        services = Services.query.all()
        return services

    @api.response(201, 'Service successfully created.')
    @api.expect(service)
    def post(self):

        """
        creates a service
        * Send a JSON object with GBU ID and SERVICE in the request body
         ```
        {
            "GBU_ID": GBU ID
            "SERVICE": "New Service name"
        }
        ```
        """

        data = request.json

        create_service(data)


        return None, 201



@ns.route('/<int:id>')
@api.response(404, 'Service not found.')
class ServiceItem(Resource):

    @api.doc('get_service')
    @api.marshal_with(service_with_vulnerabilities)
    def get(self, id):

        '''Returns a service with a list of vulnerabilities checked'''

        return Services.query.filter(Services.SERVICE_ID == id).one()


    @api.doc('update a service')
    @api.expect(service)
    @api.response(204, 'Service successfully updated.')
    def put(self, id):
        """
        Updates a service.
        Use this method to change the name of a service and its gbu.

        * Send a JSON object with the new names in the request body.
        ```
        {
            "GBU_ID": New GBU ID
            "SERVICE": "New Service name"
        }
        ```

        * specify the ID of the service to modify in the request URL path.
        """

        data = request.json
        update_service(id, data)
        return None, 204

    @api.response(204, 'Service successfully deleted. ')
    def delete(self, id):
        """

        Deletes a service

        """

        delete_service(id)
        return None, 204