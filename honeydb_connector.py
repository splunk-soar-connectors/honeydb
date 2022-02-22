# File: honeydb_connector.py
#
# Copyright (c) 2018-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import json

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from honeydb_consts import BASE_URL


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class HoneydbConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(HoneydbConnector, self).__init__()

        self._state = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code,
            error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        headers = {'X-HoneyDb-ApiId': self._api_id,
                   'X-HoneyDb-ApiKey': self._api_key}

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = BASE_URL + endpoint

        try:
            r = request_func(
                url,
                json=data,
                headers=headers,
                params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to HoneyDB")
        # make rest call
        ret_val, response = self._make_rest_call('/bad-hosts', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ip = param['ip']
        feed = param.get('feed', 'both')

        if feed.lower() not in ('bad hosts', 'twitter', 'both'):
            message = "Invalid option '{}'. Select 'Both', 'Bad Hosts', or 'Twitter'".format(feed)
            action_result.set_status(phantom.APP_ERROR, message)
            return action_result.get_status()

        feed = feed.lower()

        summary = action_result.update_summary({})
        summary['ip'] = ip
        summary['bad_hosts_count'] = 0
        summary['bad_hosts_last_seen'] = None
        summary['twitter_count'] = 0
        summary['twitter_last_seen'] = None

        if feed in ('bad hosts', 'both'):
            # These are hosts that have sent info back to the HoneyDB.
            self.save_progress("Requesting host info...")

            ret_val, ips = self._make_rest_call(
                '/bad-hosts',
                action_result, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # so just return from here
                return action_result.get_status()
            if len(ips) > 0:
                for dict_ip in ips:
                    if ip == dict_ip['remote_host']:
                        action_result.add_data({
                            'ip': ip,
                            'feed': 'Bad Hosts',
                            'count': int(dict_ip['count']),
                            'last_seen': dict_ip['last_seen'],
                            'tweet': {
                                'id': None,
                                'created': None,
                                'screen_name': None,
                                'text': None,
                            }})
                        summary['bad_hosts_count'] = int(dict_ip['count'])
                        summary['bad_hosts_last_seen'] = dict_ip['last_seen']

        if feed in ('twitter', 'both'):
            ret_val, ips = self._make_rest_call(
                '/twitter-threat-feed',
                action_result, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            if len(ips) > 0:
                twitter_count = summary['twitter_count']
                twitter_last_seen = summary['twitter_last_seen']
                for dict_ip in ips:
                    if ip == dict_ip['remote_host']:
                        twitter_count = int(dict_ip['count'])
                        twitter_last_seen = dict_ip['last_seen']

                # Only call 'twitter-threat-feed' with the ip if we found an IP, otherwise it would
                # be weird if it found some additional tweets
                ret_val, tweets = self._make_rest_call(
                    '/twitter-threat-feed/{}'.format(ip),
                    action_result, params=None, headers=None)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()

                for tweet in tweets:
                    action_result.add_data({
                        'ip': ip,
                        'feed': 'Twitter',
                        'count': twitter_count,
                        'last_seen': twitter_last_seen,
                        'tweet': {
                            'id': tweet['tweet_id'],
                            'created': tweet['created'],
                            'screen_name': tweet['screen_name'],
                            'text': tweet['tweet_text'],
                        }})
                summary['twitter_count'] = twitter_count
                summary['twitter_last_seen'] = twitter_last_seen

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        self._api_id = config['api_id']
        self._api_key = config['api_key']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-verify', '--verify_cert', help='verify certificate', action='store_true')

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify_cert = args.verify_cert

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify_cert, timeout=30)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify_cert, data=data, headers=headers, timeout=30)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HoneydbConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
