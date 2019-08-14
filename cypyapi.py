#!/usr/bin/env python3
"""
    new_cylance.py: Validates list of workstations from QRadar reference set against Cylance to determine if Cylance
    is properly reporting/installed on the workstation.

    - Workstation reference set has a TTL of 24-hours

    Author: Justin Robinson
    Version: 2.0

    #TODO:
    - Check for the install token in the registry as part of the check.
    - Check workstation name format for anomalies in spelling/format
    - Output Region based on first three characters.
"""

import requests
import json
from datetime import datetime, timedelta
import warnings
import pytz
from base64 import b64decode
import postgre_conn as pc
from psycopg2.extras import execute_values
from cypyapi.cypyapi import CyPyAPI as cypy

warnings.filterwarnings("ignore")

# QRadar Prod
qradar_server = '10.181.90.15'
refset = 'IVZ source workstation list'
headers = {'SEC': 'e1e45e71-3d2d-41df-a0c5-9e082b0ce77a', 'content-type': 'application/json', 'version': '9.0'}

app_id = 'b6179952-ff25-4bb3-a2a1-8d1aee1e1fa0'  # Claim (sub) - required to generate Cylance token
app_secret = 'b9a536d3-224d-4073-aec9-b61dd7eb40ce'  # Signature - required to generate Cylance token
tenant_id = '89cc64ed-49ae-4ca4-ae94-ba10a31b5158'  # (tid) - required to generate Cylance token
auth_endpoint = 'https://protectapi.cylance.com/auth/v2/token'  # Endpoint to Cylance API

# Dev Database
dev = True
# report_path = r'\\houdata04\IT Services\CAS\Security\tulz\Reporting\Cylance' + '\\'
db_host = 'USAPPPYTHWT100'
db_name = 'sofc_dash'
db_user = 'corp-app-secmon'
db_pass = str(b64decode('JXVfYXdBYzVAaWVwcU0wK0YzNkNOb3ZMPw==').decode('utf-8'))
db_port = 8443

# Dev Database

# Dates
hou_tz = pytz.timezone('US/Central')
utc_tz = pytz.utc
cur_utc_datetime = utc_tz.localize(datetime.utcnow())  # UTC
cur_central_datetime = cur_utc_datetime.astimezone(hou_tz)  # US/Central

# PostgreSQL Database connection
postgres_obj = pc.PostgresConnect(db_host, db_name, db_user, db_pass)
postgres_conn = postgres_obj.connect(db_port)
postgres_curs = postgres_conn.cursor()


def main():
    # New Cylance object.
    cylance_obj = cypy(tenant_id, app_id, app_secret)

    # Get a list of devices found in Cylance.
    print('[*] Gathering list of devices found in Cylance')
    cylance_devices = cylance_obj.get_devices()
    print('[*] Found ' + str(len(cylance_devices)) + ' devices\n')
    for device in cylance_devices:


    # Get a list of threats found in Cylance.
    print('[*] Gathering list of threats found in Cylance')
    cylance_threats = cylance_obj.get_threats()
    print('[*] Found ' + str(len(cylance_threats)) + ' threats\n')

    # Get a list of items on either the global blocklist or safelist
    print('[*] Gathering the Global Quarantine list')
    cy_quarantine = cylance_obj.get_global_list(0)
    print('[*] Global Quarantine List contains ' + str(len(cy_quarantine)) + ' items\n')

    print('[*] Gathering the Global Quarantine list')
    cy_safelist = cylance_obj.get_global_list(1)
    print('[*] Global Quarantine List contains ' + str(len(cy_safelist)) + ' items\n')

    # Get a list of devices found in QRadar reference set.
    print('[*] Gathering the list of devices found in QRadar')
    qradar_devices = get_refset_devices()
    print('[* Found ' + str(len(qradar_devices)) + ' devices.\n')

    # Compare the lists to find out which devices aren't reporting to Cylance.
    dnr = devices_not_reporting(cylance_devices, qradar_devices)

    # Store the list of devices and time.
    #store_devices(dnr)

    # Store Cylance threats in Postgre DB.
    # store_threats(cylance_threats)

    # Store global quarantine list in Postgre DB.
    # store_gbl_list(cy_quarantine, 0)
    # store_gbl_list(cy_safelist, 1)

    # Retrieve Events with given timedelta
    # td = timedelta(days=7)  # 7 Days
    # devices_7 = retrieve_events_time(td)
    # json_output(devices_7, 'not_reporting_7days.json')

    if not dev:
        # After writing the file. Clear the reference set.
        requests.delete('https://' + qradar_server + '/api/reference_data/sets/' + refset + '?purge_only=true',
                        headers=headers,
                        verify=False
                        )
        print('[*] Reference Set Purged')

    postgres_conn.close()


def get_refset_devices():
    """
        Get a list of devices from reference set 'IVZ source workstation list'.
        This list contains successful workstations logons in the last 3 days.

    :return:
    """
    workstations = []

    response = requests.get('https://' + qradar_server + '/api/reference_data/sets/' + refset,
                            headers=headers,
                            verify=False
                            )

    body = json.loads(response.content)
    rs_data = body['data']

    for workstation in rs_data:
        workstations.append(str(workstation['value']).upper())

    return workstations


def devices_not_reporting(cylance_devices, qradar_devices):
    """
        Print the input list of devices to a .json file.
    :return:
    """
    # Add devices that aren't found in Cylance to separate list.
    devices = []
    for device in qradar_devices:
        if device not in cylance_devices:
            entry = [device, str(cur_utc_datetime)]
            devices.append(entry)

    return devices


def store_devices(device_list):
    """

    :param device_list:
    :return:
    """
    postgres_query = 'INSERT INTO cy_workstations_not_reporting (workstation_name, reported_time) VALUES %s'
    execute_values(postgres_curs, postgres_query, device_list)

    if postgres_conn.commit():
        print('[*] Non-reporting devices saved to Postgres DB.')


def json_output(events, filename):
    """

    :param devices:
    :return:
    """
    # Save to JSON file
    print('[!] ' + report_path + filename)

    try:
        with open(report_path + filename, 'w') as outfile:
            data = json.dumps(events, indent=4, sort_keys=True, separators=(',', ': '), ensure_ascii=False)
            outfile.write(data)
    except FileNotFoundError as fnf_error:
        print(
            r'File not found. ' + str(fnf_error))
    except PermissionError as perm_error:
        print(
            r'You don\'t have permission to ' + report_path
            + str(perm_error))
    finally:
        print('[*] Write Complete')


def store_threats(threats_list):
    """

    :return:
    """
    postgres_query = 'INSERT INTO cy_threats (name,sha256,md5,cylance_score,av_industry,classification,sub_class,' \
                     'global_quarantine,safelist,file_size,unique_to_cylance,last_found,logged_time) VALUES %s'
    execute_values(postgres_curs, postgres_query, threats_list)

    if postgres_conn.commit():
        print('[*] Non-reporting devices saved to Postgres DB.')


def store_gbl_list(items_list, listtype):
    """

    :return:
    """

    if listtype == 0:
        table = 'cy_quarantine'
    elif listtype == 1:
        table = 'cy_safelist'

    postgres_query = 'INSERT INTO ' + table + ' (name,sha256,md5,cylance_score,av_industry,classification,sub_class,' \
                     'list_type,category,added,added_by,reason,logged_time) VALUES %s ON CONFLICT (sha256) DO UPDATE' \
                     ' SET name=EXCLUDED.name,sha256=EXCLUDED.sha256,md5=EXCLUDED.md5,cylance_score=EXCLUDED.cylance_score,' \
                     'av_industry=EXCLUDED.av_industry,classification=EXCLUDED.classification,sub_class=EXCLUDED.sub_class,' \
                     'list_type=EXCLUDED.list_type,category=EXCLUDED.category,added=EXCLUDED.added,added_by=EXCLUDED.added_by,' \
                     'reason=EXCLUDED.reason,logged_time=EXCLUDED.logged_time'

    execute_values(postgres_curs, postgres_query, items_list)

    if postgres_conn.commit():
        print('[*] Global list saved to Postgres DB.')


if __name__ == '__main__':
    main()
