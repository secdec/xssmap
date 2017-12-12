##
## Application Security Threat Attack Modeling (ASTAM)
##
## Copyright (C) 2017 Applied Visions - http://securedecisions.com
##
## Written by Aspect Security - http://aspectsecurity.com
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

"""
XssMapObject.py
"""

import base64
import json
import random

import requests

from PageRenderAPI import PageRenderAPI
from XssMapPayloads import TRIGGER_VALUE_PLACEHOLDER, XSSMAP_PAYLOADS

class XssScanner(object):
    """
    Performs active scanning for cross-site scription.
    """

    def __init__(self, scan_parameters):
        """
        XssScanner is initialized by an XssMapObject, which can come from ReflectionChecker
        or RequestVariableProbe.

        Args:
            scan_parameters (XssMapObject)
        """

        self.load_new_parameters(scan_parameters)

        self.headers = {}
        self.cookies = {}

    def add_headers(self, headers):
        """
        Add headers

        Args:
            headers (list)
        """

        self.headers = headers

    def add_cookies(self, cookies):
        """
        Add cookies

        Args:
            cookies (list)
        """

        self.cookies = cookies

    def load_new_parameters(self, scan_parameters):
        """
        Load parameters needed to perform active XSS scanning.

        Args:
            scan_parameters (XssMapObject)
        """

        self.target_url = scan_parameters.request_url_root
        self.target_type = scan_parameters.request_type
        self.params_reflected = scan_parameters.params_reflected
        self.params_other = scan_parameters.params_other

    def render_GET_page(self, attack, request_url_root, param_under_test,\
            params_reflected, params_other):
        """
        Do GET request, prepare enough webpage data to scan for XSS.

        Params:
            attack (str)
            request_url_root (str)
            param_under_test (dict)
            params_reflected (list)
            params_other (list)

        Returns:
            (obj)
        """

        all_params_to_add = params_reflected + params_other

        u = request_url_root + '?'

        for param_to_add in all_params_to_add:
            if param_to_add['name'] == param_under_test['name']:
                u = u + param_to_add['name'] + '='
                u = u + attack
            else:
                u = u + param_to_add['name'] + '=' + param_to_add['value']

        # If we ended up with trailing ampersand on URL, remove
        if u[-1] == '&':
            u = u[:-1]

        rendered_page_output = PageRenderAPI.render_page_with_phantom('GET', u, None, \
                    self.headers, self.cookies, pageEvents=True)

        return rendered_page_output

    def render_POST_page(self, attack, request_url_root, param_under_test,\
            params_reflected, params_other):
        """
        Do POST request, prepare enough webpage data to scan for XSS.

        Params:
            attack (str)
            request_root (str)
            param_under_test (dict)
            params_reflected (list)
            params_other (list)

        Returns:
            (obj)
        """

        attack_url = request_url_root
        attack_body = ''

        all_params = params_reflected + params_other
        url_params_to_add = []
        body_params_to_add = []

        # Sort all parameters by delivery method - URL or body
        for param in all_params:
            if param['delivery'] == 'url':
                url_params_to_add.append(param)
            elif param['delivery'] == 'body':
                body_params_to_add.append(param)

        added_question_mark_to_url = False
        for param in url_params_to_add:
            if added_question_mark_to_url is False:
                attack_url += '?'
                added_question_mark_to_url = True
            if param['name'] == param_under_test['name']:
                attack_url += param['name'] + '='
                attack_url += attack
            else:
                attack_url += param['name'] + '=' + param['value']

        # If we ended up with trailing ampersand on URL, remove
        if attack_url[-1] == '&':
            attack_url = attack_url[:-1]

        for param in body_params_to_add:
            if param['name'] == param_under_test['name']:
                attack_body += param['name'] +'='
                attack_body += attack
            else:
                attack_body += param['name'] + '=' + param['value']

        # If we ended up with trailing ampersand in body, remove
        if attack_body and attack_body[-1] == '&':
            attack_body = attack_body[:-1]

        self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        rendered_page_output = PageRenderAPI.render_page_with_phantom('POST', attack_url, attack_body, \
            self.headers, self.cookies, pageEvents=True)

        return rendered_page_output

    def make_trigger(self):
        """
        Makes an XSS scan trigger string - 9 digit number.

        Returns:
            (str)
        """

        return str(random.randrange(100000000, 999999999))

    def __analyze_rendered_page_output(self, rendered_page_output, search=None):
        """
        (Private) Check for XSS in a rendered page output object and return results.

        Args:
            rendered_page_output (obj)

            {
                'page_html' : string of page's rendered html
                'page_errors' : list of strings of javascript error()
                'page_console_message' : list of strings of javascript console.log()
                'page_confirms' : list of strings of javascript confirm()
                'page_prompts' : list of strings of javascript prompt()
            }

        Returns:
            (list)
        """

        results = []

        if search is not None:
            # Currently all our attacks cause an alert with the trigger
            for alert in rendered_page_output['page_alerts']:
                # If we find the trigger in an alert, assume XSS
                if search in alert:
                    result = {}
                    result['certainty'] = 'CERTAIN'
                    msg = 'Indicated via alert: "' + alert + '"'
                    result['message'] = msg
                    results.append(result)

            # JS errors
            for error in rendered_page_output['page_errors']:
                if search in error:
                    result = {}
                    result['certainty'] = 'PROBABLE'
                    msg = 'Indicated via execution error: "' + error + '"'
                    result['message'] = msg
                    results.append(result)

            # JS console messages
            for console_msg in rendered_page_output['page_console_messages']:
                if search in console_msg:
                    result = {}
                    result['certainty'] = 'PROBABLE'
                    msg = 'Indicated via console message: "' + console_msg + '"'
                    result['message'] = msg
                    results.append(result)

        return results

    def run(self):
        """
        Run main functionality.

        Returns:
            (XssMapObject)
        """

        output = []

        for param_reflected in self.params_reflected:
            used_payloads = []
            for context in param_reflected['reflect_contexts']:
                for payload in XSSMAP_PAYLOADS:
                    if context == 'general' or context in payload['contexts']:
                        if payload['id'] in used_payloads:
                            continue
                        else:
                            used_payloads.append(payload['id'])
                        trigger_str = self.make_trigger()
                        attack = payload['string'].replace(TRIGGER_VALUE_PLACEHOLDER, trigger_str)

                        rendered_page_output = None
                        if self.target_type == 'GET':
                            rendered_page_output = self.render_GET_page(attack, self.target_url, \
                                    param_reflected, self.params_reflected, self.params_other)
                        elif self.target_type == 'POST':
                            rendered_page_output = self.render_POST_page(attack,\
                                    self.target_url, param_reflected, self.params_reflected,\
                                    self.params_other)

                        results = self.__analyze_rendered_page_output(rendered_page_output, \
                                trigger_str)

                        for result in results:
                            result['parameter'] = param_reflected['name']
                            result['deliver'] = param_reflected['delivery']
                            result['attack'] = attack
                            output.append(result)

        return output
