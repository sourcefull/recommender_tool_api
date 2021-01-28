from database import db
from sqlalchemy import Integer, String, Float
from sqlalchemy.orm import relationship


class VulRecord(db.Model):
    __tablename__ = 'vulnerabilityrecord'

    ID = db.Column(Integer, primary_key = True)
    VULN_ID = db.Column(String)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False)
    services = relationship("Services", back_populates="vulnerabilityrecord")


class Vulnerabilities(db.Model):

    __tablename__ = 'vulnerabilities'

    ID = db.Column(Integer, primary_key=True)
    VULN_ID = db.Column(String)
    VERSION = db.Column(String)
    VECTORSTRING = db.Column(String)
    EXPLOIT_SCORE = db.Column(String)


class UserProfile(db.Model):

    __tablename__ = 'userprofile'

    USER_PROFILE_ID = db.Column(Integer, primary_key=True)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False)
    DOMAIN_PROFILE_ID = db.Column(Integer, db.ForeignKey('domainprofile.DOMAIN_PROFILE_ID'), nullable=False)
    CONFIDENTIALITY_IMPACT = db.Column(Integer)
    INTEGRITY_IMPACT = db.Column(Integer)
    AVAILABILITY_IMPACT = db.Column(Integer)
    PRIVILEGES_REQUIRED = db.Column(Integer)
    USER_INTERACTION = db.Column(Integer)
    SCOPE = db.Column(Integer)
    ATTACK_COMPLEXITY = db.Column(Integer)
    ACCESS_VECTOR = db.Column(Integer)

    services = relationship("Services", back_populates="userprofile")
    domainprofile = relationship("DomainProfile", back_populates="userprofile")
    implicitprofile = relationship("ImplicitProfile", back_populates="userprofile", cascade="all, delete")


class ImplicitProfile(db.Model):

    __tablename__ = 'implicitprofile'

    IMPLICIT_PROFILE_ID = db.Column(Integer, primary_key=True)
    USER_PROFILE_ID = db.Column(Integer, db.ForeignKey('userprofile.USER_PROFILE_ID'), nullable=False, unique = True)
    DOMAIN_PROFILE_ID = db.Column(Integer, db.ForeignKey('domainprofile.DOMAIN_PROFILE_ID'), nullable=False)#, nullable=False)
    CONFIDENTIALITY_IMPACT = db.Column(Float, nullable = False)
    INTEGRITY_IMPACT = db.Column(Float, nullable = False)
    AVAILABILITY_IMPACT = db.Column(Float, nullable = False)
    PRIVILEGES_REQUIRED = db.Column(Float, nullable = False)
    USER_INTERACTION = db.Column(Float, nullable = False)
    SCOPE = db.Column(Float, nullable = False)
    ATTACK_COMPLEXITY = db.Column(Float, nullable = False)
    ACCESS_VECTOR = db.Column(Float, nullable = False)

    domainprofile = relationship("DomainProfile", back_populates="implicitprofile")
    userprofile = relationship("UserProfile", back_populates="implicitprofile")


class DomainProfile(db.Model):

    __tablename__ = 'domainprofile'

    DOMAIN_PROFILE_ID = db.Column(Integer, primary_key = True)
    GBU_ID = db.Column(Integer, db.ForeignKey('gbus.GBU_ID'), nullable=False, unique=True)
    CONFIDENTIALITY_IMPACT = db.Column(Integer)
    INTEGRITY_IMPACT = db.Column(Integer)
    AVAILABILITY_IMPACT = db.Column(Integer)
    PRIVILEGES_REQUIRED = db.Column(Integer)
    USER_INTERACTION = db.Column(Integer)
    SCOPE = db.Column(Integer)
    ATTACK_COMPLEXITY = db.Column(Integer)
    ACCESS_VECTOR = db.Column(Integer)

    userprofile = relationship("UserProfile", back_populates="domainprofile", cascade="all, delete")
    implicitprofile = relationship("ImplicitProfile", back_populates="domainprofile", cascade="all, delete")
    gbus = relationship("GBUs", back_populates="domainprofile")


"""
class CveVulnerabilities(db.Model):
    __tablename__ = 'cvevulnerabilities'

    VULN_ID = db.Column(Integer, primary_key = True)
    CVE_ID = db.Column(String)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False)
"""


class GBUs(db.Model):
    __tablename__ = 'gbus'

    GBU_ID = db.Column(Integer, primary_key = True)
    GBU = db.Column(String)
    services = relationship('Services', back_populates = "gbus", cascade = "all, delete")
    domainprofile = relationship('DomainProfile', back_populates = "gbus", cascade = "all, delete")

class Services(db.Model):
    __tablename__ = 'services'


    SERVICE_ID = db.Column(Integer, primary_key=True)
    GBU_ID = db.Column(Integer, db.ForeignKey('gbus.GBU_ID'), nullable=False)
    SERVICE = db.Column(String)
    #VERSION = db.Column(String)
    #Cvevulnerabilities = relationship("CveVulnerabilities", cascade="all, delete")
    vulnerabilityrecord = relationship("VulRecord", back_populates = "services", cascade="all, delete")
    gbus = relationship("GBUs", back_populates="services")
    userprofile = relationship("UserProfile", back_populates = "services", cascade = "all, delete")