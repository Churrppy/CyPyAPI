#! /usr/bin/env Python
"""
    Author: Justin Robinson
    Version: 1.0
    Updated: 2019-08-21
    Contact: justin@roguetechconsulting.com

    Endpoints: Devices, Global List, Policy, Threat, User, Zone

    Future:
        - JSON/CSV Output Function
        - Ability to load credentials from file
        - Check that the access_token has appropriate scope before running the function.

    TODO:
        - When to use error codes and when to use exceptions

"""
import requests
from . import exceptions as exception
import json
import jwt
import uuid
import logging
from datetime import datetime, timedelta
import re

# --------------------------------------------  VARIABLES -- CHANGE AS NEEDED  --------------------------------------- #
region_codes = ['apne1', 'au', 'euc1', 'sae1']

services = {
            'auth': 'auth/v2/',
            'users': 'users/v2/',
            'threats': 'threats/v2/',
            'devices': 'devices/v2/',
            'globallists': 'globallists/v2/',
            'zones': 'zones/v2/',
            'policies': 'policies/v2/'
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

agent = {
    'product': ['Protect', 'Optics'],
    'os': ['CentOS7', 'Linux', 'Mac', 'Ubuntu1404', 'Ubuntu1604', 'Windows'],
    'architecture': ['X86', 'X64', 'CentOS6', 'CentOS6UI', 'CentOS7', 'CentOS7UI', 'Ubuntu1404', 'Ubuntu1404UI', 'Ubuntu1604', 'Ubuntu1604UI'],
    'package': ['Exe', 'Msi', 'Dmg', 'Pkg']
}

# scopes = {
#
# }
# ----------------------------------------  DO NOT EDIT BELOW THIS LINE  --------------------------------------------- #


class CyPyAPI:
    """
        A Cylance API Wrapper Class developed in Python 3.7
    """

    def __init__(self, tenant_id, app_id, app_secret, region_code='na'):
        """

        """
        # Create a new logging configuration
        # Levels: Debug, Info, Warning, Error, Critical
        logging_format = '%(created)f - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(filename='cypyapi.log', filemode='w', format=logging_format)

        # Set the appropriate Service Endpoint based on the Region Code.
        if region_code is 'na':
            self.base_endpoint = 'https://protectapi.cylance.com/'
            logging.info('NA Base Endpoint selected.')
        elif region_code is 'us-gov':
            self.base_endpoint = 'https://protectapi.us.cylance.com/'
            logging.info('US-GOV Base Endpoint selected.')
        elif region_code in region_codes:
            self.base_endpoint = 'https://protectapi-' + region_code + '.cylance.com/'
            logging.info(str(region_code) + ' Base Endpoint selected.')
        else:
            logging.error('Invalid region code provided')
            raise

        # These are used when generating access tokens
        try:
            self.tenant_id = tenant_id
            self.app_id = app_id
            self.app_secret = app_secret
        except UnboundLocalError as no_assignment:
            logging.error('Missing Tenant ID, App ID, or App Secret when initiating object creation')
            exit(2)

        # Set an empty access_token variable for later.
        self.access_token = ''

        # Set an empty timeout variable to track the timeout of the current token. EPOCH format.
        self.timeout = 0

    @staticmethod
    def get_headers(access_token):
        """ Returns a dict containing the headers with an updated access token """
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + str(access_token)
        }

        return headers

    @staticmethod
    def resp_code_check(response_code):
        """
            This method take a response code from a Cylance API request. Checks it for success, and returns an
            exception if the response returns an error, True if the response is 200, or False if the response errored
            with anything else.

        :param response_code:
        :return:
        """

        if response_code == 400:
            raise exception.Response400Error
        elif response_code == 401:
            raise exception.Response401Error
        elif response_code == 403:
            raise exception.Response403Error
        elif response_code == 404:
            return exception.Response404Error
        elif response_code == 409:
            raise exception.Response409Error
        elif response_code == 500:
            raise exception.Response500Error
        elif response_code == 501:
            raise exception.Response501Error
        elif response_code == 200 or response_code == 202:
            return True
        else:
            raise exception.ResponseError(response_code)

    def token_timeout_check(self):
        """
            This function can be used to check if the current token is expired/timed out. Returns a Bool.
        :return:
        """
        now = datetime.utcnow()
        epoch_now = int((now - datetime(1970, 1, 1)).total_seconds())

        # Return True if the token is still active; False if the token is expired.
        if epoch_now >= self.timeout:
            return True
        else:
            return False

    def get_access_token(self, timeout=1800):
        """

        :return:
        """
        # The longest time-span a token can have is 30 minutes.
        if timeout > 1800:
            logging.error('Maximum token timeout exceeded. Must not exceed 1800 seconds.')
            raise exception.MaxTimeoutExceeded

        else:
            # Create some time variables to set token expiry and issued time
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
                'iss': 'http://cylance.com',  # Issuer -- Don't Change It
                'sub': self.app_id,
                'tid': self.tenant_id,
                'jti': jti_val  # SECURITY: Store this in a DB table and check against each access attempt to detect impersonation attacks.
                # 'scp' :
            }

            # Encode the request with JWT.
            encoded_req = jwt.encode(claims, self.app_secret, algorithm='HS256')

            payload = {'auth_token': str(encoded_req, 'utf-8')}
            headers = {'Content-Type': 'application/json; charset=utf-8'}
            response = requests.post(str(self.base_endpoint + services['auth'] + 'token'), headers=headers,
                                     data=json.dumps(payload))

            if self.resp_code_check(response.status_code):
                response_content = json.loads(response.content)
                # Set access token.
                self.access_token = response_content['access_token']

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
        # TODO

    def get_users(self, page_num=0, page_size=200):
        """
            Request a page with a list of users. Sorted by created date, in descending order.

        :return:
        """
        users = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before each request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['users']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        users.append(item)
                    current_page += 1

                else:
                    break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['users']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    users.append(item)

        return users

    def get_user(self, identifier):
        """
            Request a specific console user.

            The identifier can be either a user_id or an email address.

        :return:
        """
        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['users'] + identifier),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code) and content['page_items']:
            for item in content['page_items']:
                return item

    def update_user(self):
        """
            Update a console user.
        :return:
        """
        # TODO

    def delete_user(self):
        """
            Delete a console user
        :return:
        """
        # TODO

    def send_invite_email(self):
        """

        :return:
        """
        # TODO

    def send_reset_pass_email(self):
        """

        :return:
        """
        # TODO

    def get_devices(self, page_num=0, page_size=200):
        """
            Request a page with a list of a device resources. Sorted by created date in descending order.

            {
              "page_number": 0,
              "page_size": 0,
              "total_pages": 0,
              "total_number_of_items": 0,
              "page_items": [
                {
                  "id": "string",
                   "name”: “string",
                   "state": “string",
                   "agent_version": "string",
                   "policy": {
                     “id": "string",
                      “name": "string"
                  },
                  "date_first_registered": "2017-07-28T16:35:46.081Z",
                  “ip_addresses”: [
                     “string1”,
                     “string2” ],
                  “mac_addresses”: [
                     “string1”,
                     “string2” ]
                }
              ]
            }
        :return:
        """
        devices = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1
            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before each request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['devices']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        devices.append(item)
                    current_page += 1

                else:
                    break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['devices']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                # If there are page_items in the content then cycle through them and add them to the list.
                for item in content['page_items']:
                    devices.append(item)

        return devices

    def get_device(self, device_id):
        """
            Request information on a device.

            {
                "id": "string",
                 "name": "string",
                 "host_name": "string",
                 "os_version": "string",
                 "state": "string",
                 "agent_version": "string",
                 "policy": {
                    “id": "string",
                     “name": "string"
                },
                "last_logged_in_user": "string",
                "update_type": "string",
                "update_available": true,
                "background_detection": true,
                "is_safe": true,
                "date_first_registered": "2017-06-15T18:02:45.714Z",
                "date_offline": "2017-06-15T18:02:45.714Z",
                "date_last_modified": "2017-06-15T18:02:45.714Z",
                  “ip_addresses”: [
                     “string1”,
                     “string2” ],
                  “mac_addresses”: [
                     “string1”,
                     “string2” ]
            }
        :return:
        """

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['devices'] + device_id), headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code) and content['page_items']:
            for item in content['page_items']:
                return item

    def update_device(self, device_id):
        """
            Update a console device
        :return:
        """
        # TODO

    def get_device_threats(self, device_id, page_num=0, page_size=200):
        """
            Requests a page with a list of threats found on a specific device.

            {
                "page_number": 0,
                "page_size": 0,
                "total_pages": 0,
                "total_number_of_items": 0,
                "page_items": [
                    {
                        "name": "string",
                        "sha256”: “string",
                        "file_status": 0,
                        "file_path": "string",
                        "cylance_score": 0,
                        "classification": "string",
                        "sub_classification": "string",
                        "date_found": "2017-06-15T18:02:45.714Z"
                    }
                ]
            }

        :param device_id:
        :return:
        """
        device_threats = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before the entire request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['devices'] + device_id + '/threats'),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        device_threats.append(item)
                    current_page += 1

                else:
                    break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['devices'] + device_id + '/threats'),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    device_threats.append(item)

        return device_threats

    def get_zone_devices(self, zone_id, page_num=0, page_size=200):
        """

        :return:
        """
        """
                    Request a page with a list of a device resources. Sorted by created date in descending order.

                    {
                      "page_number": 0,
                      "page_size": 0,
                      "total_pages": 0,
                      "total_number_of_items": 0,
                      "page_items": [
                        {
                          "id": "string",
                           "name”: “string",
                           "state": “string",
                           "agent_version": "string",
                           "policy": {
                             “id": "string",
                              “name": "string"
                          },
                          "date_first_registered": "2017-07-28T16:35:46.081Z",
                          “ip_addresses”: [
                             “string1”,
                             “string2” ],
                          “mac_addresses”: [
                             “string1”,
                             “string2” ]
                        }
                      ]
                    }
                :return:
                """
        zone_devices = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1
            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before each request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['devices'] + zone_id + '/devices'),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and response.content['page_items']:
                    for item in content['page_items']:
                        zone_devices.append(item)
                    current_page += 1

                else:
                    break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['devices']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    zone_devices.append(item)

        return zone_devices

    def get_agent_installer_link(self, product, os, package, architecture=None, build=None):
        """

        :param product:
        :param os:
        :param package:
        :param architecture:
        :param build:
        :return:
        """
        params = {}

        # Building the parameters
        if product in agent['product']:
            params['product'] = product

            if (os == 'Windows' or os == 'Mac') and (architecture is None or package is None):
                logging.error('Architecture or package missing.')
                exit(2)
            elif os is None:
                logging.error('No OS type provided')
                exit(2)
            else:
                params['os'] = os

                if architecture is not None:
                    if architecture in agent['architecture']:
                        params['architecture'] = architecture
                    else:
                        logging.error('Architecture selected does not exist')
                        exit(2)
                if package is not None:
                    if package in agent['package']:
                        params['package'] = package
                    else:
                        logging.error('Packaged selected does not exist')
                        exit(2)
                if build is not None:
                    if build in agent['build']:
                        params['build'] = build
                    else:
                        logging.error('Build selected does not exist')
                        exit(2)
        else:
            logging.error('Invalid product. Must be either Protect or Optics.')

        # set an access token
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['devices'] + 'installer'),
                                headers=self.get_headers(self.access_token),
                                params=params)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code) and content['page_items']:
            for item in content['page_items']:
                return item

    def update_device_threat(self, device_id):
        """
            Waive or Quarantine a convicted threat on a device.
        :param device_id:
        :return:
        """
        # TODO

    def delete_devices(self, callback_url, device_ids=[], method='delete'):
        """
            This function supports an optional callback_url, as well as a JSON list of device ID's. Maximum 20.

        :return:
        """
        if not device_ids:
            logging.error('No Device IDs existed in the provided list')
            exit(2)

        if not callback_url:
            data = {
                'device_ids': device_ids,
            }
        else:
            data = {
                'device_ids': device_ids,
                'callback_url': callback_url
            }

        # Generate a new access token before each request for security.
        self.get_access_token()
        if method == 'delete':
            response = requests.delete(str(self.base_endpoint + services['devices']),
                                       headers=self.get_headers(self.access_token),
                                       data=data)
        elif method == 'post':
            response = requests.post(str(self.base_endpoint + services['devices'] + 'delete'),
                                     headers=self.get_headers(self.access_token),
                                     data=data)
        else:
            logging.error('Invalid method selected for this function.')
            exit(2)

        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            # As long as the response code is 202. The response will contain a request_id.
            return content['request_id']

    def get_device_by_mac(self, mac_address):
        """
            Request a device resource by using a MAC address.

            Formats Accepted:
            00-00-00-00-00-00
            00:00:00:00:00:00

        :param mac_address:
        :return:
        """
        mac_patt = r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$'
        mac_re = re.compile(mac_patt)

        if not mac_re.match(mac_address):
            logging.error('Improperly formatted MAC address')
            exit(2)

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['devices'] + 'macaddress/' + mac_address),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content


    def get_global_list(self, list_type, page_num=0, page_size=200):
        """
            Get a list of global list resources.

            {
              "page_number": 0,
              "page_size": 0,
              "total_pages": 0,
              "total_number_of_items": 0,
              "page_items": [
                {
                  "name": "string",
                  "sha256": "string",
                  "md5": "string",
                  "cylance_score": 0,
                  "av_industry": 0,
                  "classification": "string",
                  "sub_classification": "string",
                  "list_type": "string",
                  "category": "string",
                  "added": "2017-05-22T23:35:56.705Z",
                  "added_by": "string",
                  "reason": "string"
                }
              ]
            }

            list_type = 0 or 1 (0 = Global Quarantine :: 1 = Global Safe)

        :param list_type:
        :return:
        """
        if 0 != list_type != 1:
            raise exception.InvalidListType

        glist = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size,
                    'listTypeId': list_type
                }

                # Generate a new access token before each request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['globallists']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code):
                    if content['page_items']:
                        for item in content['page_items']:
                            glist.append(item)
                        current_page += 1

                    else:
                        break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size,
                'listTypeId': list_type
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['globallists']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                if content['page_items']:
                    for item in content['page_items']:
                        glist = item

        return glist

    def add_global_list(self, sha256_hash, list_type, category, reason):
        """
            Add to a global list
        :return:
        """
        if 0 != list_type != 1:
            raise exception.InvalidListType

        if 64 > len(sha256_hash) > 64:  # TODO: Find better ways of checking for valid user input so that it is more exact.
            raise exception.InvalidSHA256Error

        request = {
            'sha256': sha256_hash,
            'list_type': list_type,
            'category': category,
            'reason': reason
        }

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['globallists']), data=request)

        if self.resp_code_check(response.status_code):
            content = json.loads(response.content)
            confirmation = content[0]

            return confirmation

    def delete_global_list(self, list_type, sha256_hash):
        """
            Delete from a global list
        :return:
        """
        if 0 != list_type != 1:
            raise exception.InvalidListType

        if 64 > len(sha256_hash) > 64:  # TODO: Find better ways of checking for valid user input so that it is more exact.
            raise exception.InvalidSHA256Error

        request = {
            'sha256': sha256_hash,
            'list_type': list_type,
        }

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['globallists']), data=request)

        if self.resp_code_check(response.status_code):
            content = json.loads(response.content)
            confirmation = content[0]

            return confirmation

    def get_threat(self, sha256_hash):
        """
            Request threat details on a specific hash
        :param sha256_hash:
        :return:
        """
        if 64 > len(sha256_hash) > 64:
            raise exception.InvalidSHA256Error

        else:
            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['threats'] + sha256_hash), headers=self.headers)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                content = json.loads(response.content)
                return content[0]

    def get_threats(self, page_num=0, page_size=200):
        """
            Request a page with a list of console threat resources. Sorted by last found date, in descending order.

        Response
        {
            "page_number": 0,
            "page_size": 0,
            "total_pages": 0,
            "total_number_of_items": 0,
            "page_items": [
                {
                    "name": "string",
                    "sha256": "string",
                    "md5": "string",
                    "cylance_score": 0,
                    "av_industry": 0,
                    "classification": "string",
                    "sub_classification": "string",
                    "global_quarantined": true,
                    "safelisted": true,
                    "file_size": 0,
                    "unique_to_cylance": true
                    "last_found": "2017-06-15T21:35:11.994Z"
                }
            ]
        }
        :return:
        """
        threats = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before the entire request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['threats']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code):
                    if content['page_items']:
                        for item in content['page_items']:
                            threats.append(item)
                        current_page += 1

                    else:
                        break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['threats']), headers=self.get_headers(self.access_token), params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                if content['page_items']:
                    for item in content['page_items']:
                        threats.append(item)

        return threats

    def get_threat_devices(self, hash_, page_num=0, page_size=200):
        """
           Request a list of MAC addresses and IP addresses associated with a specific threat(hash).

           Response
           {
                "page_number": 0,
                "page_size": 0,
                "total_pages": 0,
                "total_number_of_items": 0,
                "page_items": [
                    {
                        "id": "string",
                        "name": "string",
                        "state": "Offline",
                        "agent_version": "string",
                        "policy_id": "string",
                        "date_found": "2017-06-15T21:35:11.994Z",
                        "file_status": "Quarantined",
                        "file_path": "string",
                        "ip_addresses": [
                            "string1",
                            "string2" ],
                        "mac_addresses": [
                            "string1”,
                            "string2” ]
                    }
                ]
            }

        :param hash:
        :return:
        """
        devices = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            # Generate a new access token before the entire request for security.
            self.get_access_token()

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                response = requests.get(str(self.base_endpoint + services['threats'] + hash_ + '/devices'), params=params)

                if self.resp_code_check(response.status_code):
                    if response.content['page_items']:
                        content = json.loads(response.content)
                        devices.append(content[0])
                        # TODO: Comment this.
                        current_page += 1

                    else:
                        break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['threats'] + hash_ + '/devices'), params=params)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                content = json.loads(response.content)
                devices = content[0]

        return devices

    def get_threat_download_link(self, hash_):
        """

        :return:
        """
        # set an access token
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['threats'] + 'download/' + hash_))

        if self.resp_code_check(response.status_code):
            content = json.loads(response.content)
            return content[0]

    def get_zones(self, page_num=0, page_size=200):
        """
            {
                "page_number": 0,
                "page_size": 0,
                "total_pages": 0,
                "total_number_of_items": 0,
                "page_items": [
                    {
                        "id": "string",
                        "name": "string",
                        "criticality": "string",
                        "zone_rule_id": "string",
                        "policy_id": "string",
                        “update_type”: “string”,
                        "date_created": "2017-06-15T21:35:11.994Z",
                        "date_modified": "2017-06-15T21:35:11.994Z"
                    }
                ]
            }
        :return:
        """
        zones = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            # Generate a new access token before each request for security.
            self.get_access_token()

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                response = requests.get(str(self.base_endpoint + services['zones']), params=params)

                if self.resp_code_check(response.status_code):
                    if response.content['page_items']:
                        content = json.loads(response.content)
                        zones.append(content[0])
                        # TODO: Comment this.
                        current_page += 1

                    else:
                        break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['zones']), params=params)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                content = json.loads(response.content)
                zones = content[0]

        return zones

    def get_device_zones(self, device_id, page_num=0, page_size=200):
        """
            {
                "page_number": 0,
                "page_size": 0,
                "total_pages": 0,
                "total_number_of_items": 0,
                "page_items": [
                    {
                        "id": "string",
                        "name": "string",
                        "criticality": "string",
                        "zone_rule_id": "string",
                        "policy_id": "string",
                        “update_type”: “string”,
                        "date_created": "2017-06-15T21:35:11.994Z",
                        "date_modified": "2017-06-15T21:35:11.994Z"
                    }
                ]
            }

        :param device_id:
        :param page_num:
        :param page_size:
        :return:
        """
        # TODO: Check for a valid device_id

        zones = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1

            # Generate a new access token before this request, for security.
            self.get_access_token()

            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                response = requests.get(str(self.base_endpoint + services['zones'] + device_id + '/zones'), params=params)

                if self.resp_code_check(response.status_code):
                    if response.content['page_items']:
                        content = json.loads(response.content)
                        zones.append(content[0])
                        # TODO: Comment this.
                        current_page += 1

                    else:
                        break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['zones'] + device_id + '/zones'), params=params)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                content = json.loads(response.content)
                zones = content[0]

        return zones

    def get_zone(self, device_id):
        """
            Request threat details on a specific hash
        :param device_id:
        :return:
        """
        # TODO: Check for a valid device_id

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['zones'] + device_id), headers=self.headers)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            content = json.loads(response.content)
            return content[0]

    def create_zone(self):
        """

        :return:
        """
        # TODO

    def update_zone(self):
        """

        :return:
        """
        # TODO

    def delete_zone(self, zone_id):
        """

        :return:
        """
        # TODO: Create an exception like the commented one below to check for a valid zone_id
        # if 64 > len(
        #         sha256_hash) > 64:
        #     raise exception.InvalidSHA256Error

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['zones'] + zone_id))

        if self.resp_code_check(response.status_code):
            content = json.loads(response.content)
            confirmation = content[0]

            return confirmation

    def get_policy(self, policy_id):
        """ """
        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['policies'] + policy_id),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code) and content['page_items']:
            for item in content['page_items']:
                return item

    def get_policies(self, page_num=0, page_size=200):
        """ """
        policies = []

        # If the page number is less than 1, we have to loop through the pages to get them all
        if page_num == 0:
            # Set the current page to 1
            current_page = 1
            while True:
                # Set the initial page and the maximum page_size.
                params = {
                    'page': current_page,
                    'page_size': page_size
                }

                # Generate a new access token before each request for security.
                self.get_access_token()
                response = requests.get(str(self.base_endpoint + services['policies']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        policies.append(item)
                    current_page += 1

                else:
                    break

        else:
            # Set the parameters of the request.
            params = {
                'page': page_num,
                'page_size': page_size
            }

            # Generate a new access token before each request for security.
            self.get_access_token()
            response = requests.get(str(self.base_endpoint + services['policies']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                # If there are page_items in the content then cycle through them and add them to the list.
                for item in content['page_items']:
                    policies.append(item)

        return policies

    def create_policy(self):
        """ """

    def update_policy(self):
        """ """

    def delete_policy(self):
        """ """

    def delete_policies(self):
        """ """
