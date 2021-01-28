from flask_sqlalchemy import SQLAlchemy
import os
db = SQLAlchemy()
import json
import pandas as pd
from database.models import VulRecord, Vulnerabilities, UserProfile, ImplicitProfile, DomainProfile, Services
import pickle
def reset_database():


    db.drop_all()
    db.create_all()





def db_seed():

    nvd_df = pickle.load(open("nvd_df.p", "rb"))

    for i in range(len(nvd_df)):
        cve = nvd_df.iloc[i]['VULNID']
        version = nvd_df.iloc[i]['VERSION']
        vector = nvd_df.iloc[i]['VECTOR_STRING']
        exploit_score = nvd_df.iloc[i]['EXPLOIT_SCORE']

        vul_entry = Vulnerabilities(VULN_ID=cve,
                                    VERSION=version,
                                    VECTORSTRING=vector,
                                    EXPLOIT_SCORE=exploit_score)
        db.session.add(vul_entry)


    db.session.commit()

    print('database seeded!')

