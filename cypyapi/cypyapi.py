#! /usr/bin/env python
"""
    __author__ = "Justin Robinson"
    __copyright__ = "Copyright 2019, Rogue Technology Consulting"
    __license__ = "MIT"
    __version__ = "1.0"
    __maintainer__ = "Justin Robinson"
    __email__ = "justin@roguetechconsulting.com"
    __status__ = "Testing"

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
    Cylance API Wrapper Class developed in Python 3.7

    Args:
            tenant_id (string): See Cylance API Documentation
            app_id (string): See Cylance API Documentation
            app_secret (string): See Cylance API Documentation
            region_code (string, optional): (default: na) The region code is used to determine the base endpoint.
    """
    def __init__(self, tenant_id, app_id, app_secret, region_code='na'):
        """ Intitiate a CyPyAPI object

        This function initiates a CyPyAPI class object given the required arguments.

        Args:
            tenant_id (string): See Cylance API Documentation
            app_id (string): See Cylance API Documentation
            app_secret (string): See Cylance API Documentation
            region_code (string, optional): (default: na) The region code is used to determine the base endpoint.

        """
        # Create a new logging configuration
        # Levels: Debug, Info, Warning, Error, Critical
        logging_format = '%(created)f - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(filename='cypyapi.log', format=logging_format, level='WARNING')

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
            raise exception.InvalidRegionCode

        # These are used when generating access tokens
        try:
            self.tenant_id = tenant_id
            self.app_id = app_id
            self.app_secret = app_secret
        except NameError:
            # TODO: This may not be necessary as the Class might error out if the arguments aren't supplied on creation
            logging.error('Missing Tenant ID, App ID, or App Secret when initiating object creation')
            raise exception.UnassignedVariable

        # Set an empty access_token variable for later.
        self.access_token = ''

        # Set an empty timeout variable to track the timeout of the current token. EPOCH format.
        self.timeout = 0

    @staticmethod
    def get_headers(access_token):
        """ Returns a dict containing the headers with an updated access token """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer " + str(access_token)
        }

        return headers

    @staticmethod
    def resp_code_check(response_code):
        """
            This method takes an HTTP response code from a Cylance API request. Checks it for success, and returns an
            exception if the response returns an error, True if the response is 2XX, or False if the response errored
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
        elif response_code in range(200, 299):
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
            logging.info('Token timeout not exceeded.')
            return True
        else:
            logging.error('Token timeout exceeded.')
            return False

    def get_access_token(self, timeout=1800):
        """
        TODO: Add some ability to provide scope

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
                logging.info('Access token generated ' + self.access_token)

    def create_user(self, email, user_role, first_name, last_name, zones=[]):
        """
            Create a new console user.

        :param email: string
        :param user_role: string
        :param first_name: string
        :param last_name: string
        :param zones: list
        :return:
        """
        # Build the data params DICT to submit
        data = {
            "email": email,
            "user_role": user_role,
            "first_name": first_name,
            "last_name": last_name,
            "zones": zones
        }
        data = json.dumps(data)

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['users']),
                                 headers=self.get_headers(self.access_token),
                                 data=data)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            # Return the post user response schema or False
            return content

    def get_users(self, page_num=0, page_size=200):
        """
            Request a list of console users

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
            Get information on a specific user.

        :return:
        """
        if not identifier:
            logging.error('No identifer provided to get_user')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['users'] + identifier),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content

    def update_user(self, identifier, email, user_role, first_name, last_name, zones=[]):
        """
            Update a console user.

        :return:
        """
        # Build the data params DICT to submit
        if not identifier:
            logging.error('No identifier provided to update_user')
            raise ValueError

        data = {
            "email": email,
            "user_role": user_role,
            "first_name": first_name,
            "last_name": last_name,
            "zones": zones
        }
        data = json.dumps(data)

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.put(str(self.base_endpoint + services['users'] + identifier),
                                headers=self.get_headers(self.access_token),
                                data=data)

        if self.resp_code_check(response.status_code):
            return True

    def delete_user(self, user_id):
        """
            Delete a console user.
        :return:
        """
        if not user_id:
            logging.error('No User ID provided to delete_user')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['users'] + user_id),
                                   headers=self.get_headers(self.access_token))

        if self.resp_code_check(response.status_code):
            return True

    def send_invite_email(self, user_email):
        """
            Re-send console invite. Return True if successful.

        :return:
        """
        if not user_email:
            logging.error('No User Email was provided to send_invite_email')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['users'] + user_email + '/invite'),
                                 headers=self.get_headers(self.access_token))

        if self.resp_code_check(response.status_code):
            return True

    def send_reset_pass_email(self, user_email):
        """
            Request a console password reset

        :return:
        """
        if not user_email:
            logging.error('No user Email was provided to send_reset_pass_email')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['users'] + user_email + '/resetpassword'),
                                 headers=self.get_headers(self.access_token))

        if self.resp_code_check(response.status_code):
            return True

    def get_devices(self, page_num=0, page_size=200):
        """
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
        :return:
        """
        if not device_id:
            logging.error('No Device ID was provided to get_device')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['devices'] + device_id),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content

    def update_device(self, device_id, name, policy_id, add_zone_ids=[], remove_zone_ids=[]):
        """
            Update a console device

        :return:
        """
        if not device_id:
            logging.error('No Device ID was provided to update_device')
            raise ValueError

        # Build the data params DICT to submit
        data = {
            "name": name,
            "policy_id": policy_id,
            "add_zone_ids": add_zone_ids,
            "remove_zone_ids": remove_zone_ids
        }
        data = json.dumps(data)

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.put(str(self.base_endpoint + services['devices'] + device_id),
                                headers=self.get_headers(self.access_token),
                                data=data)

        if self.resp_code_check(response.status_code):
            return True

    def get_device_threats(self, device_id, page_num=0, page_size=200):
        """
        :param device_id:
        :return:
        """
        if not device_id:
            logging.error('No Device ID provided to update_device')
            raise ValueError()

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
        if not zone_id:
            logging.error('No Zone ID provided to get_zone_devices')
            raise ValueError

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
            response = requests.get(str(self.base_endpoint + services['devices'] + zone_id + '/devices'),
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

            if (os == 'Windows' or os == 'Mac') and (architecture is None and package is None):
                logging.error('Package and architecture were not selected.')
                raise ValueError
            elif os is None:
                logging.error('Operating System not selected. See agent{} at the beginning of the script.')
                raise ValueError
            else:
                params['os'] = os

                if architecture is not None:
                    if architecture in agent['architecture']:
                        params['architecture'] = architecture
                    else:
                        logging.error('Invalid architecture. See agent{} at the beginning of the script')
                        raise exception.InvalidArchitecture
                if package is not None:
                    if package in agent['package']:
                        params['package'] = package
                    else:
                        logging.error('Invalid package. See agent{} at the beginning of the script')
                        raise exception.InvalidPackage
                if build is not None:
                    if build in agent['build']:
                        params['build'] = build
                    else:
                        logging.error('Invalid build. See agent{} at the beginning of the script')
                        raise exception.InvalidBuild

        else:
            logging.error('Invalid product. Must be either Protect or Optics.')
            raise exception.InvalidProduct

        # set an access token
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['devices'] + 'installer'),
                                headers=self.get_headers(self.access_token),
                                params=params)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            return content['url']

    def update_device_threat(self, device_id, threat_id, event):
        """
            Waive or Quarantine a convicted threat on a device.
        :param device_id:
        :return:
        """
        if not device_id:
            logging.error('No Device ID provided to update_device_threat')
            raise ValueError
        if not threat_id:
            logging.error('No Threat ID (SHA256) provided to update_device_threat')
            raise ValueError
        if not event:
            logging.error('No event was provided to update_device_threat')
            raise ValueError
        if 64 > len(threat_id) > 64:
            raise exception.InvalidSHA256Error

        # Build the data params DICT to submit
        data = {
            "threat_id": threat_id,  # SHA256
            "event": event  # Quarantine or Waive
        }
        data = json.dumps(data)

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['devices'] + device_id + '/threats'),
                                 headers=self.get_headers(self.access_token),
                                 data=data)

        if self.resp_code_check(response.status_code):
            return True

    def delete_devices(self, callback_url, device_ids=[], method='delete'):
        """
            This function supports an optional callback_url, as well as a JSON list of device ID's. Maximum 20.
            Provides an optional method parameter if your client does not support DELETE.

        :return:
        """
        if not device_ids:
            logging.error('No Device IDs provided to delete_devices')
            raise ValueError

        if not callback_url:
            data = {
                "device_ids": device_ids,
            }
        else:
            data = {
                "device_ids": device_ids,
                "callback_url": callback_url
            }

        # Ensure that the data is formatted for JSON
        data = json.dumps(data)

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
            raise exception.InvalidMethod

        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            # As long as the response code is 202. The response will contain a request_id.
            return content

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
            raise exception.InvalidMAC

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

        :param list_type:
        :return:
        """
        if 0 != list_type != 1:
            logging.error('Invalid list type. Must be either 0 (SafeList) or 1 (Quarantine)')
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
            logging.error('Invalid list type. Must be either 0 (SafeList) or 1 (Quarantine)')
            raise exception.InvalidListType

        if 64 > len(sha256_hash) > 64:
            logging.error('Invalid SHA256')
            raise exception.InvalidSHA256Error

        request = {
            'sha256': sha256_hash,
            'list_type': list_type,
            'category': category,
            'reason': reason
        }

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['globallists']),
                                 headers=self.get_headers(self.access_token),
                                 data=request)

        if self.resp_code_check(response.status_code):
            return True

    def delete_global_list(self, list_type, sha256_hash):
        """
            Delete from a global list
        :return:
        """
        if 0 != list_type != 1:
            logging.error('Invalid list type. Must be either 0 (SafeList) or 1 (Quarantine)')
            raise exception.InvalidListType

        if 64 > len(sha256_hash) > 64:
            logging.error('Invalid SHA256')
            raise exception.InvalidSHA256Error

        request = {
            'sha256': sha256_hash,
            'list_type': list_type,
        }

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['globallists']),
                                   headers=self.get_headers(self.access_token),
                                   data=request)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            return True

    def get_threat(self, sha256_hash):
        """
            Request threat details on a specific hash
        :param sha256_hash:
        :return:
        """
        if 64 > len(sha256_hash) > 64:
            logging.error('Invalid SHA256')
            raise exception.InvalidSHA256Error

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['threats'] + sha256_hash),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content

    def get_threats(self, page_num=0, page_size=200):
        """
            Request a page with a list of console threat resources. Sorted by last found date, in descending order.

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

                if self.resp_code_check(response.status_code) and content['page_items']:
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
            response = requests.get(str(self.base_endpoint + services['threats']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    threats.append(item)

        return threats

    def get_threat_devices(self, hash_, page_num=0, page_size=200):
        """
           Request a list of MAC addresses and IP addresses associated with a specific threat(hash).

        :param hash:
        :return:
        """
        if not hash_:
            logging.error('No hash provided to get_threat_devices')
            raise ValueError

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

                response = requests.get(str(self.base_endpoint + services['threats'] + hash_ + '/devices'),
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
            response = requests.get(str(self.base_endpoint + services['threats'] + hash_ + '/devices'),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    devices.append(item)

        return devices

    def get_threat_download_link(self, sha256_hash):
        """

        :return:
        """
        if 64 > len(sha256_hash) > 64:
            logging.error('Invalid SHA256')
            raise exception.InvalidSHA256Error

        # set an access token
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['threats'] + 'download/' + sha256_hash),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            return content

    def get_zones(self, page_num=0, page_size=200):
        """
            Get a list of zones from the console

        :return:
        """
        zones = []

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

                response = requests.get(str(self.base_endpoint + services['zones']),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        zones.append(item)
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
            response = requests.get(str(self.base_endpoint + services['zones']),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code) and content['page_items']:
                for item in content['page_items']:
                    zones.append(item)

        return zones

    def get_device_zones(self, device_id, page_num=0, page_size=200):
        """
            Get a list of threats given a specific device_id

        :param device_id:
        :param page_num:
        :param page_size:
        :return:
        """
        if not device_id:
            logging.error('No Device ID provided to get_device_zones')
            raise ValueError

        zones = []

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

                # Generate a new access token before this request, for security.
                self.get_access_token()

                response = requests.get(str(self.base_endpoint + services['zones'] + device_id + '/zones'),
                                        headers=self.get_headers(self.access_token),
                                        params=params)
                content = json.loads(response.content)

                if self.resp_code_check(response.status_code) and content['page_items']:
                    for item in content['page_items']:
                        zones.append(item)
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
            response = requests.get(str(self.base_endpoint + services['zones'] + device_id + '/zones'),
                                    headers=self.get_headers(self.access_token),
                                    params=params)
            content = json.loads(response.content)

            # Validates the response code, and returns an exception if the request is not a success.
            if self.resp_code_check(response.status_code):
                for item in content['page_items']:
                    zones.append(item)

        return zones

    def get_zone(self, device_id):
        """
            Request threat details on a specific hash
        :param device_id:
        :return:
        """
        if not device_id:
            logging.error('No Device ID provided to get_zone')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['zones'] + device_id), headers=self.headers)
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content

    def create_zone(self, name, policy_id, criticality):
        """

        :return:
        """
        if not name:
            logging.error('No user ID included with call to create_policy')
            raise ValueError
        if not policy_id:
            logging.error('No policy included with call to create_policy')
            raise ValueError
        if not criticality:
            logging.error('No criticality included with call to create_policy')
            raise ValueError

            # Build the data params DICT to submit
        data = {
            "name": name,
            "policy_id": policy_id,
            "criticality": criticality
        }

        # Ensure that the data is formatted for JSON
        data = json.dumps(data)

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['zones']),
                                 headers=self.get_headers(self.access_token),
                                 data=data)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            # Return the unique identifier of the new zone
            return content

    def update_zone(self, zone_id, name, policy_id, criticality):
        """
            Update Zone in console

        :return:
        """
        if not zone_id:
            logging.error('No zone ID included with call to create_policy')
            raise ValueError
        if not name:
            logging.error('No user ID included with call to create_policy')
            raise ValueError
        if not policy_id:
            logging.error('No policy included with call to create_policy')
            raise ValueError
        if not criticality:
            logging.error('No criticality included with call to create_policy')
            raise ValueError

        # Build the data params DICT to submit
        data = {
            "name": name,
            "policy_id": policy_id,
            "criticality": criticality
        }
        data = json.dumps(data)

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.put(str(self.base_endpoint + services['zones'] + zone_id),
                                headers=self.get_headers(self.access_token),
                                data=data)

        if self.resp_code_check(response.status_code):
            return True

    def delete_zone(self, zone_id):
        """
            Given a valid Zone ID, return True if the zone was successfully removed.
        :return:
        """
        if not zone_id:
            logging.error('No Zone ID provided to delete_zone')
            raise ValueError

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['zones'] + zone_id))

        if self.resp_code_check(response.status_code):
            return True

    def get_policy(self, policy_id):
        """ """
        if not policy_id:
            logging.error('No Policy ID provided to get_policy')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.get(str(self.base_endpoint + services['policies'] + policy_id),
                                headers=self.get_headers(self.access_token))
        content = json.loads(response.content)

        # Validates the response code, and returns an exception if the request is not a success.
        if self.resp_code_check(response.status_code):
            return content

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
                for item in content['page_items']:
                    policies.append(item)

        return policies

    def create_policy(self, user_id, policy={}):
        """
            Create a new within Cylance. Returns the newly created policy_id if successful. Otherwise it returns False.

        :param user_id:
        :param policy:
        :return:
        """
        if not user_id:
            logging.error('No user ID included with call to create_policy')
            raise ValueError
        if not policy:
            logging.error('No policy included with call to create_policy')
            raise ValueError

        # Build the data params DICT to submit
        data = {
            "user_id": user_id,
            "policy": policy
        }

        # Ensure that the data is formatted for JSON
        data = json.dumps(data)

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.post(str(self.base_endpoint + services['policies']),
                                 headers=self.get_headers(self.access_token),
                                 data=data)
        content = json.loads(response.content)

        if self.resp_code_check(response.status_code):
            return content

    def update_policy(self, user_id, policy={}):
        """
            Given unique user_id and policy dict, update the policy.
        :param user_id:
        :param policy:
        :return:
        """
        if not user_id:
            logging.error('No user ID included with call to create_policy')
            raise ValueError
        if not policy:
            logging.error('No policy included with call to create_policy')
            raise ValueError

        # Build the data params DICT to submit
        data = {
            "user_id": user_id,
            "policy": policy
        }
        data = json.dumps(data)

        # Generate a new access token before each request, for security.
        self.get_access_token()
        response = requests.put(str(self.base_endpoint + services['policies']),
                                headers=self.get_headers(self.access_token),
                                data=data)
        content = json.loads(response.content)

        # The return will always with a HTTP204 according to the API doc.
        if self.resp_code_check(response.status_code):
            return content

    def delete_policy(self, policy_id):
        """
            Delete a console user.

        :return:
        """
        if not policy_id:
            logging.error('No User ID provided to delete_user')
            raise ValueError

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['policies'] + policy_id),
                                   headers=self.get_headers(self.access_token))

        # The return will always with a HTTP204 according to the API doc.
        if self.resp_code_check(response.status_code):
            return True

    def delete_policies(self, policy_ids=[]):
        """
            This function supports an optional callback_url, as well as a JSON list of device ID's. Maximum 20.
            Provides an optional method parameter if your client does not support DELETE.

        :return:
        """
        if not policy_ids:
            logging.error('No Device IDs existed in the provided list')
            raise ValueError

        data = {
            "tenant_policy_ids": policy_ids,
        }

        # Ensure that the data is formatted for JSON
        data = json.dumps(data)

        # Generate a new access token before each request for security.
        self.get_access_token()
        response = requests.delete(str(self.base_endpoint + services['policies']),
                                   headers=self.get_headers(self.access_token),
                                   data=data)

        if self.resp_code_check(response.status_code):
            # The return will always with a HTTP204 according to the API doc.
            return True
