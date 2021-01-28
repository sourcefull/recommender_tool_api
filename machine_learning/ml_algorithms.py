from database.models import Vulnerabilities, Services, DomainProfile, UserProfile, VulRecord, ImplicitProfile
from database import db
import numpy as np
import pandas as pd

from flask import request, jsonify



def update_mer_mma(implicitprofile, v):


    conf_impact = implicitprofile.CONFIDENTIALITY_IMPACT
    int_impact = implicitprofile.INTEGRITY_IMPACT
    avail_impact = implicitprofile.AVAILABILITY_IMPACT
    privil_required = implicitprofile.PRIVILEGES_REQUIRED
    user_interaction = implicitprofile.USER_INTERACTION
    scope = implicitprofile.SCOPE
    attack_complex = implicitprofile.ATTACK_COMPLEXITY
    access_vec = implicitprofile.ACCESS_VECTOR

    u_hat_array = np.array([conf_impact, int_impact, avail_impact, attack_complex, privil_required, user_interaction, scope,
                            access_vec])/10

    S = 3
    u_hat = ((S-1)*u_hat_array + v)/S
    return (u_hat * 10)


def createCVEdict(cve):

    #result = Vulnerabilities.query.filter_by(VULN_ID = cve).first()
    vuln_df = pd.read_sql(sql=db.session.query(Vulnerabilities).with_entities(Vulnerabilities.VULN_ID,
                                                                         Vulnerabilities.VERSION,
                                                                         Vulnerabilities.VECTORSTRING,
                                                                         Vulnerabilities.EXPLOIT_SCORE).statement,
                                                                         con=db.session.bind)

    cve_df = vuln_df[vuln_df['VULN_ID'] == cve].reset_index(drop=True)
    base_metric = cve_df.iloc[0]['VERSION']



    cve_dict = dict()

    conv_dict = dict()
    attvec_dict = dict()
    conv_dict['H'] = 'HIGH'
    conv_dict['L'] = 'LOW'
    conv_dict['N'] = 'NONE'
    conv_dict['R'] = 'REQUIRED'
    conv_dict['U'] = 'UNCHANGED'
    conv_dict['C'] = 'CHANGED'
    conv_dict['NS'] = 'NO_SCOPE'
    attvec_dict['N'] = 'NETWORK'
    attvec_dict['A'] = 'ADJACENT'
    attvec_dict['L'] = 'LOCAL'
    attvec_dict['P'] = 'PHYSICAL'

    def list_to_dict(rlist):
        return dict(map(lambda s: s.split(':'), rlist))
    vec_string = cve_df.iloc[0]['VECTORSTRING']
    exploitscore = cve_df.iloc[0]['EXPLOIT_SCORE']

    def convert_vec_dict(vec_dict):

        #Attack complexity conversion
        if vec_dict['AC'] == 'H':
            vec_dict['UI'] = 'R'
        elif vec_dict['AC'] == 'M':
            vec_dict['UI'] = 'R'
            vec_dict['AC'] = 'L'
        else:
            vec_dict['UI'] = 'N'


        #Authorization conversion
        if vec_dict['Au'] == 'M':
            vec_dict['PR'] = 'H'
        elif vec_dict['Au'] == 'S':
            vec_dict['PR'] = 'L'
        else:
            vec_dict['PR'] = 'N'

        if vec_dict['C'] == 'C':

            vec_dict['C'] = 'H'
        elif vec_dict['C'] == 'P':
            vec_dict['C'] = 'L'


        if vec_dict['I'] == 'C':
            vec_dict['I'] = 'H'
        elif vec_dict['I'] == 'P':
            vec_dict['I'] = 'L'

        if vec_dict['A'] == 'C':
            vec_dict['A'] = 'H'
        elif vec_dict['A'] == 'P':
            vec_dict['A'] = 'L'

        vec_dict['S'] = 'NS'

        return vec_dict



    if (base_metric == 'baseMetricV3'):
        vec_list = vec_string.split('/')[1:]
        vec_dict = list_to_dict(vec_list)

    else:
        vec_list = vec_string.split('/')
        vec_dict = list_to_dict(vec_list)
        vec_dict = convert_vec_dict(vec_dict)

    cve_dict['confidentiality_impact'] = conv_dict[vec_dict['C']]
    cve_dict['integrity_impact'] = conv_dict[vec_dict['I']]
    cve_dict['availability_impact'] = conv_dict[vec_dict['A']]
    cve_dict['exploitability_score'] = float(exploitscore)
    cve_dict['att_complex'] = conv_dict[vec_dict['AC']]
    cve_dict['privileges_required'] = conv_dict[vec_dict['PR']]
    cve_dict['user_interaction'] = conv_dict[vec_dict['UI']]
    cve_dict['scope'] = conv_dict[vec_dict['S']]
    cve_dict['attack_vector'] = attvec_dict[vec_dict['AV']]






    return cve_dict






def vulnerability_vec(cve):
    impact_dict = dict()
    impact_dict['NONE'] = 0
    impact_dict['LOW'] = 0.5
    impact_dict['HIGH'] = 1.0

    AV_dict = dict()
    AV_dict['NETWORK'] = 1.0
    AV_dict['ADJACENT_NETWORK'] = 0.6
    AV_dict['LOCAL'] = 0.3
    AV_dict['PHYSICAL'] = 0

    AC_dict = dict()
    AC_dict['LOW'] = 1.0
    AC_dict['HIGH'] = 0

    PR_dict = dict()
    PR_dict['NONE'] = 1.0
    PR_dict['LOW'] = 0.5
    PR_dict['HIGH'] = 0

    UI_dict = dict()
    UI_dict['NONE'] = 1.0
    UI_dict['REQUIRED'] = 0

    Scope_dict = dict()
    Scope_dict['CHANGED'] = 1.0
    Scope_dict['NO_SCOPE'] = 0.5
    Scope_dict['UNCHANGED'] = 0



    cve_dict = createCVEdict(cve)


    # impact feature vectors
    confidentiality_score = impact_dict[cve_dict['confidentiality_impact']]
    integrity_score = impact_dict[cve_dict['integrity_impact']]
    availability_score = impact_dict[cve_dict['availability_impact']]

    # exploitability
    # this determines the ease of exploiting the vulnerability
    exploitability_score = cve_dict['exploitability_score']

    #exploit features
    att_complex_score = AC_dict[cve_dict['att_complex']]
    priv_required_score = PR_dict[cve_dict['privileges_required']]
    user_interaction_score = UI_dict[cve_dict['user_interaction']]
    scope_score = Scope_dict[cve_dict['scope']]
    attack_vec_score = AV_dict[cve_dict['attack_vector']]

    return np.array([confidentiality_score, integrity_score, availability_score, exploitability_score,
                     att_complex_score, priv_required_score, user_interaction_score, scope_score, attack_vec_score])


def get_profilevec(df):

    confidentiality_score = (df.iloc[0]['CONFIDENTIALITY_IMPACT']) / 10
    integrity_score = (df.iloc[0]['INTEGRITY_IMPACT']) / 10
    availability_score = (df.iloc[0]['AVAILABILITY_IMPACT']) / 10
    attack_vector_score = (df.iloc[0]['ACCESS_VECTOR']) / 10
    att_complex_score = (df.iloc[0]['ATTACK_COMPLEXITY']) / 10
    privileges_required_score = (df.iloc[0]['PRIVILEGES_REQUIRED']) / 10
    user_interaction_score = (df.iloc[0]['USER_INTERACTION']) / 10
    scope_score = (df.iloc[0]['SCOPE']) / 10

    return np.asarray(
        [confidentiality_score, integrity_score, availability_score, att_complex_score, privileges_required_score,
         user_interaction_score, scope_score, attack_vector_score])



def calculate_score(gbu_id, service_id, cve):

    #gbu = data.get('0')
    #service_id = data.get('SERVICE_ID')
    #cve = data.get('CVE')


    vul_exists = Vulnerabilities.query.filter(Vulnerabilities.VULN_ID==cve).one()
    #if (not vul_exists):
    #    return jsonify(message="No service exists for that GBU and Service name"), 404

    service_exists = Services.query.filter(Services.SERVICE_ID==service_id).one()

    user_profile = service_exists.userprofile

    w_df = pd.read_sql(sql=db.session.query(DomainProfile).with_entities(DomainProfile.SCOPE,
                                                                         DomainProfile.ATTACK_COMPLEXITY,
                                                                         DomainProfile.GBU_ID,
                                                                         DomainProfile.USER_INTERACTION,
                                                                         DomainProfile.PRIVILEGES_REQUIRED,
                                                                         DomainProfile.ACCESS_VECTOR,
                                                                         DomainProfile.AVAILABILITY_IMPACT,
                                                                         DomainProfile.INTEGRITY_IMPACT,
                                                                         DomainProfile.CONFIDENTIALITY_IMPACT).statement,
                       con=db.session.bind)
    w_df = w_df[w_df['GBU_ID'] == gbu_id]

    exist_record = VulRecord.query.filter_by(VULN_ID=cve, SERVICE_ID=service_id).first()
    if (not exist_record):
        new_vul_record = VulRecord(VULN_ID=cve,
                                   SERVICE_ID=service_id)
        new_vul_record.services = service_exists

        db.session.add(new_vul_record)
        db.session.commit()

    u_df = pd.read_sql(sql=db.session.query(UserProfile).with_entities(UserProfile.SCOPE,
                                                                       UserProfile.ATTACK_COMPLEXITY,
                                                                       UserProfile.USER_INTERACTION,
                                                                       UserProfile.PRIVILEGES_REQUIRED,
                                                                       UserProfile.ACCESS_VECTOR,
                                                                       UserProfile.AVAILABILITY_IMPACT,
                                                                       UserProfile.INTEGRITY_IMPACT,
                                                                       UserProfile.CONFIDENTIALITY_IMPACT,
                                                                       UserProfile.SERVICE_ID,
                                                                       UserProfile.USER_PROFILE_ID).statement,
                       con=db.session.bind)
    u_df = u_df[u_df['SERVICE_ID'] == service_id]  # getting user profile from the service id

    userprofile_id = u_df.iloc[0]['USER_PROFILE_ID']

    u_hat_df = pd.read_sql(sql=db.session.query(ImplicitProfile).with_entities(ImplicitProfile.SCOPE,
                                                                               ImplicitProfile.ATTACK_COMPLEXITY,
                                                                               ImplicitProfile.INTEGRITY_IMPACT,
                                                                               ImplicitProfile.USER_INTERACTION,
                                                                               ImplicitProfile.PRIVILEGES_REQUIRED,
                                                                               ImplicitProfile.ACCESS_VECTOR,
                                                                               ImplicitProfile.AVAILABILITY_IMPACT,
                                                                               ImplicitProfile.CONFIDENTIALITY_IMPACT,
                                                                               ImplicitProfile.USER_PROFILE_ID).statement,
                           con=db.session.bind)

    u_hat_df = u_hat_df[u_hat_df['USER_PROFILE_ID'] == userprofile_id]  # getting the implicit profile from the user profile

    w = get_profilevec(w_df)
    u = get_profilevec(u_df)
    u_hat = get_profilevec(u_hat_df)

    v = vulnerability_vec(cve)
    score = recom_score(u, u_hat, w, v)
    final_score = round(10 * score, 2)
    return final_score


def sim_dist(t, v):
    """

    Input
    ----------
    t : Type numpy array
        DESCRIPTION. user profile feature vector
    v : TYPE numpy array
        DESCRIPTION. vulnerability feature vector

    Returns
    -------
    TYPE numpy array
        DESCRIPTION the similarity of each of the features between t and v

    """

    conf_sim = 1 - abs(t[0] - v[0])
    integrity_sim = 1 - abs(t[1] - v[1])
    availability_sim = 1 - abs(t[2] - v[2])
    exploit_sim = 1 - abs(10 - v[3]) / 10
    attack_complex_sim = 1 - abs(t[3] - v[4])
    priv_sim = 1 - abs(t[4] - v[5])
    interact_sim = 1 - abs(t[5] - v[6])
    scope_sim = 1 - abs(t[6] - v[7])
    attack_sim = 1 - abs(t[7] - v[8])

    return np.array(
        [conf_sim, integrity_sim, availability_sim, exploit_sim, attack_complex_sim, priv_sim, interact_sim, scope_sim,
         attack_sim])


def recom_score(u, u_hat, w, v):
    sim_wv = sim_dist(w, v)
    sim_uv = sim_dist(u, v)
    sim_uhatv = sim_dist(u_hat, v)

    conf_plus = 0.3 * sim_wv[0] + 0.35 * sim_uv[0] + 0.35 * sim_uhatv[0]
    integrity_plus = 0.3 * sim_wv[1] + 0.35 * sim_uv[1] + 0.35 * sim_uhatv[1]
    avail_plus = 0.3 * sim_wv[2] + 0.35 * sim_uv[2] + 0.35 * sim_uhatv[2]

    exploit_plus = 0.8 * sim_uv[3] + 0.2 * sim_uhatv[3]

    complex_plus = 0.3 * sim_wv[4] + 0.35 * sim_uv[4] + 0.35 * sim_uhatv[4]

    priv_plus = 0.3 * sim_wv[5] + 0.35 * sim_uv[5] + 0.35 * sim_uhatv[5]

    interac_plus = 0.3 * sim_wv[6] + 0.35 * sim_uv[6] + 0.35 * sim_uhatv[6]

    scope_plus = 0.3 * sim_wv[7] + 0.35 * sim_uv[7] + 0.35 * sim_uhatv[7]

    attack_plus = 0.3 * sim_wv[8] + 0.35 * sim_uv[8] + 0.35 * sim_uhatv[8]

    U_output = (conf_plus + integrity_plus + avail_plus + exploit_plus + complex_plus + priv_plus +
                interac_plus + scope_plus + attack_plus) / 9

    return U_output












