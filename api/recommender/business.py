from database import db
from database.models import UserProfile, ImplicitProfile, DomainProfile, Services, GBUs
from machine_learning.ml_algorithms import vulnerability_vec, update_mer_mma
import numpy as np


def update_service(service_id, data):
    service = Services.query.filter(Services.SERVICE_ID == service_id).one()
    gbu_id = data.get('GBU_ID')
    service.gbus = GBUs.query.filter(GBUs.GBU_ID == gbu_id).one()
    service.SERVICE = data.get('SERVICE')
    db.session.add(service)
    db.session.commit()



def delete_service(service_id):
    service = Services.query.filter(Services.SERVICE_ID==service_id).one()
    db.session.delete(service)
    db.session.commit()


def create_service(data):


    gbu_id = data.get('GBU_ID')
    gbu = GBUs.query.filter(GBUs.GBU_ID == gbu_id).one()
    service = data.get('SERVICE')


    new_service = Services(SERVICE=service)
    new_service.gbus = gbu
    db.session.add(new_service)
    db.session.commit()



def create_domain_profile(data):


    gbu_id = data.get('GBU_ID')

    gbu = GBUs.query.filter(GBUs.GBU_ID == gbu_id).one()

    confidentiality_impact = data.get('CONFIDENTIALITY_IMPACT')
    integrity_impact = data.get('INTEGRITY_IMPACT')
    availability_impact = data.get('AVAILABILITY_IMPACT')
    privileges_required = data.get('PRIVILEGES_REQUIRED')
    user_interaction = data.get('USER_INTERACTION')
    scope = data.get('SCOPE')
    attack_complexity = data.get('ATTACK_COMPLEXITY')
    access_vector = data.get('ACCESS_VECTOR')

    new_domain_profile = DomainProfile(CONFIDENTIALITY_IMPACT=confidentiality_impact,
                                       INTEGRITY_IMPACT=integrity_impact,
                                       AVAILABILITY_IMPACT=availability_impact,
                                       PRIVILEGES_REQUIRED=privileges_required,
                                       USER_INTERACTION=user_interaction,
                                       SCOPE=scope,
                                       ATTACK_COMPLEXITY=attack_complexity,
                                       ACCESS_VECTOR=access_vector)
    new_domain_profile.gbus = gbu
    db.session.add(new_domain_profile)
    db.session.commit()


def update_domain_profile(id, data):


    domain_profile = DomainProfile.query.filter(DomainProfile.DOMAIN_PROFILE_ID == id).one()
    gbu_id = data.get('GBU_ID')
    domain_profile.gbus = GBUs.query.filter(GBUs.GBU_ID==gbu_id).one()
    domain_profile.CONFIDENTIALITY_IMPACT = data.get('CONFIDENTIALITY_IMPACT')
    domain_profile.INTEGRITY_IMPACT = data.get('INTEGRITY_IMPACT')
    domain_profile.AVAILABILITY_IMPACT = data.get('AVAILABILITY_IMPACT')
    domain_profile.PRIVILEGES_REQUIRED = data.get('PRIVILEGES_REQUIRED')
    domain_profile.USER_INTERACTION = data.get('USER_INTERACTION')
    domain_profile.SCOPE = data.get('SCOPE')
    domain_profile.ATTACK_COMPLEXITY = data.get('ATTACK_COMPLEXITY')
    domain_profile.ACCESS_VECTOR = data.get('ACCESS_VECTOR')
    db.session.add(domain_profile)
    db.session.commit()



def delete_domain_profile(id):
    domain_profile = DomainProfile.query.filter(DomainProfile.DOMAIN_PROFILE_ID == id).one()
    db.session.delete(domain_profile)
    db.session.commit()

def update_implicit_profile(id, data):


    cve = data.get('CVE')
    v = vulnerability_vec(cve)
    v = np.delete(v, 3)
    implicitprofile = ImplicitProfile.query.filter(ImplicitProfile.IMPLICIT_PROFILE_ID == id).one()
    new_u_hat = update_mer_mma(implicitprofile, v)

    implicitprofile.CONFIDENTIALITY_IMPACT = new_u_hat[0]
    implicitprofile.INTEGRITY_IMPACT = new_u_hat[1]
    implicitprofile.AVAILABILITY_IMPACT = new_u_hat[2]
    implicitprofile.ATTACK_COMPLEXITY = new_u_hat[3]
    implicitprofile.PRIVILEGES_REQUIRED = new_u_hat[4]
    implicitprofile.USER_INTERACTION = new_u_hat[5]
    implicitprofile.SCOPE = new_u_hat[6]
    implicitprofile.ACCESS_VECTOR = new_u_hat[7]
    db.session.commit()







def create_user_profile(data):
    domain_id = data.get('DOMAIN_PROFILE_ID')
    domain_profile = DomainProfile.query.filter(DomainProfile.DOMAIN_PROFILE_ID ==domain_id).one()
    service_id = data.get('SERVICE_ID')
    service = Services.query.filter(Services.SERVICE_ID==service_id).one()




    confidentiality_impact = data.get('CONFIDENTIALITY_IMPACT')
    integrity_impact = data.get('INTEGRITY_IMPACT')
    availability_impact = data.get('AVAILABILITY_IMPACT')
    privileges_required = data.get('PRIVILEGES_REQUIRED')
    user_interaction = data.get('USER_INTERACTION')
    scope = data.get('SCOPE')
    attack_complexity = data.get('ATTACK_COMPLEXITY')
    access_vector = data.get('ACCESS_VECTOR')

    new_user_profile = UserProfile(CONFIDENTIALITY_IMPACT=confidentiality_impact,
                                       INTEGRITY_IMPACT=integrity_impact,
                                       AVAILABILITY_IMPACT=availability_impact,
                                       PRIVILEGES_REQUIRED=privileges_required,
                                       USER_INTERACTION=user_interaction,
                                       SCOPE=scope,
                                       ATTACK_COMPLEXITY=attack_complexity,
                                       ACCESS_VECTOR=access_vector)
    new_user_profile.domainprofile = domain_profile
    new_user_profile.services = service
    db.session.add(new_user_profile)

    new_implicit_profile = ImplicitProfile(CONFIDENTIALITY_IMPACT=confidentiality_impact,
        INTEGRITY_IMPACT=integrity_impact,
        AVAILABILITY_IMPACT=availability_impact,
        PRIVILEGES_REQUIRED=privileges_required,
        USER_INTERACTION=user_interaction,
        SCOPE=scope,
        ATTACK_COMPLEXITY=attack_complexity,
        ACCESS_VECTOR=access_vector)
    new_implicit_profile.userprofile = new_user_profile
    new_implicit_profile.domainprofile = domain_profile




    db.session.add(new_implicit_profile)

    db.session.commit()

def update_user_profile(id, data):


    user_profile = UserProfile.query.filter(UserProfile.USER_PROFILE_ID==id).one()
    domain_id = data.get('DOMAIN_PROFILE_ID')
    domain_profile = DomainProfile.query.filter(DomainProfile.DOMAIN_PROFILE_ID==domain_id).one()
    user_profile.domainprofile = domain_profile
    user_profile.CONFIDENTIALITY_IMPACT = data.get('CONFIDENTIALITY_IMPACT')
    user_profile.INTEGRITY_IMPACT = data.get('INTEGRITY_IMPACT')
    user_profile.AVAILABILITY_IMPACT = data.get('AVAILABILITY_IMPACT')
    user_profile.PRIVILEGES_REQUIRED = data.get('PRIVILEGES_REQUIRED')
    user_profile.USER_INTERACTION = data.get('USER_INTERACTION')
    user_profile.SCOPE = data.get('SCOPE')
    user_profile.ATTACK_COMPLEXITY = data.get('ATTACK_COMPLEXITY')
    user_profile.ACCESS_VECTOR = data.get('ACCESS_VECTOR')
    db.session.add(user_profile)
    db.session.commit()

def delete_user_profile(id):
    user_profile = UserProfile.query.filter(UserProfile.USER_PROFILE_ID == id).one()
    db.session.delete(user_profile)
    db.session.commit()



def update_gbu(id, data):
    gbu = GBUs.query.filter(GBUs.GBU_ID == id).one()
    gbu.GBU = data.get('GBU')
    db.session.add(gbu)
    db.session.commit()


def delete_gbu(id):
    gbu = GBUs.query.filter(GBUs.GBU_ID == id).one()
    db.session.delete(gbu)
    db.session.commit()

def create_gbu(data):
    gbu = data.get('GBU')
    new_gbu = GBUs(GBU= gbu)
    db.session.add(new_gbu)
    db.session.commit()



