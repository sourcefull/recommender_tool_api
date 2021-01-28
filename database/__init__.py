from flask_sqlalchemy import SQLAlchemy
import os
db = SQLAlchemy()
import json
import pandas as pd
from database.models import VulRecord, Vulnerabilities, UserProfile, ImplicitProfile, DomainProfile, Services

def reset_database():


    db.drop_all()
    db.create_all()


def get_nvd_df():
    path = os.getcwd()
    files = os.listdir(path + '/CVE_json')
    files_json = [f for f in files if f[-4:] == 'json']

    columns = ['VULNID', 'VERSION', 'VECTOR_STRING', 'EXPLOIT_SCORE']
    df_list = []
    for file in files_json:
        data_nvd = json.load(open(path + '/CVE_json/' + file))
        for item in data_nvd['CVE_Items']:
            cve = item['cve']['CVE_data_meta']['ID']
            if not item['impact']:
                continue

            if 'baseMetricV3' in item['impact']:
                vectorString = item['impact']['baseMetricV3']['cvssV3']['vectorString']
                version = 'baseMetricV3'
                exploit_score = item['impact']['baseMetricV3']['exploitabilityScore']
            else:
                # print(item['impact'].keys())


                vectorString = item['impact']['baseMetricV2']['cvssV2']['vectorString']
                version = 'baseMetricV2'
                exploit_score = item['impact']['baseMetricV2']['exploitabilityScore']

            list_temp = [cve, version, vectorString, exploit_score]
            my_dict = dict(zip(columns, list_temp))
            df_list.append(my_dict)

    df_artifacts = pd.DataFrame(df_list).drop_duplicates()
    return df_artifacts



def db_seed():
    nvd_df = get_nvd_df()

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

