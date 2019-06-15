#! /usr/bin/env Python
"""
    A Python3 wrapper for the CylanceProtect API.

    Author: Justin Robinson
    Version: 1.0
    Updated: 2019-06-06
    Contact: justin@roguetechconsulting.com

"""
import requests
import error.exceptions as response_exception
import json
import jwt
import uuid
import logging
import time
from datetime import datetime, timedelta

# -------------------------------------------------  VARIABLES  ------------------------------------------------------ #
# Region codes don't include North America or US Government as they have dedicated base endpoints.
region_codes = ['apne1', 'au', 'euc1', 'sae1']  # TODO: This doesn't currently do anything.

services = {
            'auth': 'auth/v2/',
            'threats': 'threats/v2/',
        }

user_roles = {  # TODO: This doesn't currently do anything.
            'user': '00000000-0000-0000-0000-000000000001',
            'administrator': '00000000-0000-0000-0000-000000000002',
            'zone_manager': '00000000-0000-0000-0000-000000000003'
        }

zone_role_types = {  # TODO: This doesn't currently do anything.
    'zone_manager': '00000000-0000-0000-0000-000000000001',
    'user': '00000000-0000-0000-0000-000000000002'
}

# scopes = {
#
# }
# ----------------------------------------  DO NOT EDIT BELOW THIS LINE  --------------------------------------------- #


class CyPyAPI:
    """

    """

    def __init__(self, tenant_id, app_id, app_secret, region_code='na'):
        """

        """
        # Create a new logging configuration
        # Levels: Debug, Info, Warning, Error, Critical
        logging_format = '%(created)f - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(filename='cypyapi-' + str(time.time()) + '.log', filemode='w', format=logging_format)

        # Set the appropriate Service Endpoint based on the Region Code.
        if region_code is 'na':
            self.base_endpoint = 'https://protectapi.cylance.com/'
        elif region_code is 'us-gov':
            self.base_endpoint = 'https://protectapi.us.cylance.com/'
        elif region_code in region_codes:
            self.base_endpoint = 'https://protectapi-' + region_code + '.cylance.com/'
        else:
            logging.error('Invalid region code provided')
            print('[!] Invalid region code provided')  # TODO: Replace with exception.

        # These are used when generating access tokens
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.app_secret = app_secret

        # Set an empty access_token variable for later.
        self.access_token = ''

        # Set an empty timeout variable to track the timeout of the current token. EPOCH format.
        self.timeout = 0

        # Setting headers.
        self.headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + self.access_token  # TODO: Check if the token is still valid
        }

    @staticmethod
    def resp_code_check(response_code):
        """
            This method take a response code from a Cylance API request. Checks it for success, and returns an
            exception if the response returns an error, True if the response is 200, or False if the response errored
            with anything else.

            # TODO: Borderline useless. Do something better this time. Return an exception, or

        :param response_code:
        :return:
        """

        if response_code == 400:
            raise response_exception.Response400Error
        elif response_code == 401:
            raise response_exception.Response401Error
        elif response_code == 403:
            raise response_exception.Response403Error
        elif response_code == 404:
            raise response_exception.Response404Error
        elif response_code == 409:
            raise response_exception.Response409Error
        elif response_code == 500:
            raise response_exception.Response500Error
        elif response_code == 501:
            raise response_exception.Response501Error
        elif response_code == 200:
            return True
        else:
            raise response_exception.ResponseError(response_code)

    def token_timeout_check(self):
        """

        :return:
        """

    def get_access_token(self, timeout=1800):
        """

        :return:
        """
        # The longest time-span a token can have is 30 minutes.
        if timeout > 1800:
            logging.error('The longest time-span a token can have is 1800 seconds (30 minutes)')
            print('[!] Timeout can not exceed 1800 seconds')  # TODO: Replace with exception.

        else:
            # Create some time objects to set token expiry and issued time
            now_utc = datetime.utcnow()
            timeout_datetime = now_utc + timedelta(seconds=timeout)
            epoch_time = int((now_utc - datetime(1970, 1, 1)).total_seconds())
            self.timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())

            # This is used to generate a unique identifier for each token.
            jti_val = str(uuid.uuid4())

            # Claims are part of the JWT request.
            claims = {
                'exp': self.timeout,
                'iat': epoch_time,
                'iss': 'http://cylance.com',  # Issuer-Don't Change It
                'sub': self.app_id,
                'tid': self.tenant_id,
                'jti': jti_val  # TODO: Store this in a DB table and check if it exists to detect impersonation attacks.
                # 'scp' :
            }

            # Encode the request with JWT.
            encoded_req = jwt.encode(claims, self.app_secret, alg='HS256')

            payload = {'auth_token': encoded_req}
            headers = {'Content-Type': 'application/json, charset=utf-8'}
            response = requests.post(str(self.base_endpoint + services['auth']), headers=headers, data=json.dumps(payload))

            if response.status_code == 200:
                print(json.loads(response.content))  # TODO: Modify this to so that this def returns the access token and its expiry.
                response_content = json.loads(response.content)
                # Set access token.
                self.access_token = response_content['access_token']

            else:
                logging.error('Error requesting access token.' + str(response.status_code))
                print('[!] Error requesting access token: ' + str(response.status_code))  # TODO: Replace with exception

    def create_user(self, email, user_role, first_name, last_name, zones=[]):
        """
        Create a new console user. Requires a unique e-mail address.

             {
             "email": "string",
             "user_role": "string",
             "first_name": "string",  # max 64 chars
             "last_name": "string",  # max 64 chars
             "zones": [  # If the user_role is Admin, this doesn't matter.
               "id": "string",
               "role_type", "string"
               "role_name", "string"
              ]
            }

        :param email: string
        :param user_role: string
        :param first_name: string
        :param last_name: string
        :param zones: dictionary
        :return:
        """

    def get_users(self):
        """
            Request a page with a list of users. Sorted by created date, in descending order.


        :return:
        """

    def get_user(self):
        """
            Request a specific console user.
        :return:
        """

    def update_user(self):
        """
            Update a console user.
        :return:
        """

    def delete_user(self):
        """
            Delete a console user
        :return:
        """

    def get_devices(self):
        """
            Request a page with a list of a device resources. Sorted by created date in descending order.
        :return:
        """

    def get_device(self):
        """
            Request information on a device.
        :return:
        """

    def update_device(self, device_id):
        """
            Update a console device
        :return:
        """

    def get_device_threats(self, device_id):
        """
            Requests a page with a list of threats found on a specific device.
        :param device_id:
        :return:
        """

    def update_device_threat(self, device_id):
        """
            Waive or Quarantine a convicted threat on a device.
        :param device_id:
        :return:
        """

    def delete_devices(self):
        """
            Delete one or more devices from an organization.
        :return:
        """

    def get_device_by_mac(self, mac_address):
        """
            Request a device resource by using a MAC address.
        :param mac_address:
        :return:
        """

    def get_global_list(self, list_type):
        """
            Get a list of global list resources.
        :param list_type:
        :return:
        """

    def add_global_list(self):
        """
            Add to a global list
        :return:
        """

    def delete_global_list(self):
        """
            Delete from a global list
        :return:
        """

    def get_threat(self, sha256_hash):
        """
            Request threat details on a specific hash
        :param hash:
        :return:
        """
        if 64 > len(sha256_hash) > 64:
            raise response_exception.InvalidSHA256Error
        else:
            response = requests.get(str(self.base_endpoint + services['threats']), headers=headers)

            # Validates the response code, and returns an exception otherwise.
            if self.resp_code_check(response['status_code']):
                content = json.loads(response.content)
                return content[0]

    def get_threats(self):
        """
            Request a page with a list of console threat resources. Sorted by last found date, in descending order.
        :return:
        """

    def get_threat_devices(self, hash):
        """
           Request a list of MAC addresses and IP addresses associated with a specific threat(hash).
        :param hash:
        :return:
        """

    def get_threat_download_link(self):
        """

        :return:
        """
