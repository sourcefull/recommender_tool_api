from flask_restx import fields
from api.restplus import api


service = api.model('service', {
    'SERVICE_ID' : fields.Integer(readOnly=True, description='The unique identifier of a service'),
    'GBU_ID' : fields.Integer(attribute = 'gbus.GBU_ID'),
    'SERVICE' : fields.String(required=True, description = 'Service name'),
})

gbu = api.model('gbu', {
    'GBU_ID' : fields.Integer(readOnly = True, description = 'The unique identifer of a GBU'),
    'GBU' : fields.String(required = True, description = 'The name of GBU'),
})


vul_record = api.model('vul record',{
    'ID' : fields.Integer(readOnly=True, description = 'The unique identifier of vulnerability record'),
    'VULN_ID' : fields.String(required = True, description='vulnerability id'),
    'SERVICE_ID' : fields.Integer(attribute = 'services.SERVICE_ID'),
    'services' : fields.String(attribute = 'services.SERVICE'),
})


service_with_vulnerabilities = api.inherit('service with vulnerabilities', service, {
    'vulnerabilities' : fields.List(fields.Nested(vul_record))

})


domain_profile = api.model('domain profile', {

    'DOMAIN_PROFILE_ID' : fields.Integer(readOnly=True, description = 'Unique identifer of domain profile'),
    'GBU_ID': fields.Integer(attribute = 'gbus.GBU_ID'),
    'GBU' : fields.String(attribute = 'gbus.GBU'),
    'CONFIDENTIALITY_IMPACT': fields.Integer(required = True, description = 'confidentiality impact rating'),
    'INTEGRITY_IMPACT': fields.Integer(required = True, description = 'integrity impact rating'),
    'AVAILABILITY_IMPACT': fields.Integer(required = True, description = 'availability impact rating'),
    'PRIVILEGES_REQUIRED': fields.Integer(required = True, description = 'privileges required rating'),
    'USER_INTERACTION': fields.Integer(required = True, description = 'user interaction rating'),
    'SCOPE': fields.Integer(required = True, description = 'scope rating'),
    'ATTACK_COMPLEXITY': fields.Integer(required = True, description = 'attack complexity rating'),
    'ACCESS_VECTOR': fields.Integer(required=True, description = 'access vector rating'),
})


gbu_with_services = api.inherit('GBU with services', gbu, {

    'services' : fields.List(fields.Nested(service)),
    'domain profiles': fields.List(fields.Nested(domain_profile)),
})



implicit_profile = api.model('implicit profile', {

    'IMPLICIT_PROFILE_ID' : fields.Integer(readOnly=True, description = 'Unique identifer of implicit profile'),
    'USER_PROFILE_ID':fields.Integer(attribute = 'userprofile.USER_PROFILE_ID'),
    'DOMAIN_PROFILE_ID':fields.Integer(attribute = 'domainprofile.DOMAIN_PROFILE_ID'),
    'CONFIDENTIALITY_IMPACT': fields.Float(required = True, description = 'confidentiality impact rating'),
    'INTEGRITY_IMPACT': fields.Float(required = True, description = 'integrity impact rating'),
    'AVAILABILITY_IMPACT': fields.Float(required = True, description = 'availability impact rating'),
    'PRIVILEGES_REQUIRED': fields.Float(required = True, description = 'privileges required rating'),
    'USER_INTERACTION': fields.Float(required = True, description = 'user interaction rating'),
    'SCOPE': fields.Float(required = True, description = 'scope rating'),
    'ATTACK_COMPLEXITY': fields.Float(required = True, description = 'attack complexity rating'),
    'ACCESS_VECTOR': fields.Float(required=True, description = 'access vector rating'),
})


user_profile = api.model('user profile', {

    'USER_PROFILE_ID' : fields.Integer(readOnly=True, description = 'Unique identifier of user profile'),
    'SERVICE_ID' : fields.Integer(attribute = 'services.SERVICE_ID'),
    'GBU': fields.String(attribute = 'domainprofile.gbus.GBU'),
    'SERVICE': fields.String(attribute = 'services.SERVICE'),
    'DOMAIN_PROFILE_ID' : fields.Integer(attribute = 'domainprofile.DOMAIN_PROFILE_ID'),
    'CONFIDENTIALITY_IMPACT': fields.Integer(required = True, description = 'confidentiality impact rating'),
    'INTEGRITY_IMPACT': fields.Integer(required = True, description = 'integrity impact rating'),
    'AVAILABILITY_IMPACT': fields.Integer(required = True, description = 'availability impact rating'),
    'PRIVILEGES_REQUIRED': fields.Integer(required = True, description = 'privileges required rating'),
    'USER_INTERACTION': fields.Integer(required = True, description = 'user interaction rating'),
    'SCOPE': fields.Integer(required = True, description = 'scope rating'),
    'ATTACK_COMPLEXITY': fields.Integer(required = True, description = 'attack complexity rating'),
    'ACCESS_VECTOR': fields.Integer(required=True, description = 'access vector rating'),
    #'IMPLICIT PROFILE': fields.Nested(implicit_profile), #(attribute = 'implicitprofile.IMPLICIT_PROFILE_ID')
})


vulnerabilities = api.model('vulnerabilities', {
    'ID' : fields.Integer(readOnly=True, description = 'Unique identifer of vulnerability'),
    'VULN_ID' : fields.String(required = True, description = 'vulnerability ID'),
    'VERSION' : fields.String(required = True, description = 'version of CVSS vector'),
    'VECTORSTRING':fields.String(required=True, description = 'CVSS vector string'),
    'EXPLOIT_SCORE':fields.String(required=True, description = 'exploitability subscore'),

})