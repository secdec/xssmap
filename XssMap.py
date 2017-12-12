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
XssMap.py
"""

import json
import re
import sys

from CommandLineUtils import handle_input
from ReflectionChecker import ReflectionChecker
from RequestVariableProbe import RequestVariableProbe
from XssMapObject import XssMapObject
from XssScanner import XssScanner

# XssMap supported JSON input version
# increment minor as we add more data, do major if we break stuff
JSON_VERSION = 1.00

class XssMap(object):
    """
    XssMap tool - finds input parameter reflection in rendered webpages,
    can actively scan for XSS.
    """

    def __init__(self, do_reflect=True, do_xss=True, cookies=[], headers=[]):
        """
        Takes arguments for whether reflection checking should be performed,
        whether XSS scanning should be performed, plus cookies and headers
        to add to outgoing HTTP requests.

        Args:
            do_reflect (bool)
            do_xss (bool)
            cookies (list)
            headers (list)
        """

        self.do_reflection_checking = do_reflect
        self.do_xss_scanning = do_xss

        self.reflection_checker = None
        self.xss_scanner = None

        self.cookies_to_add = cookies
        self.headers_to_add = headers

    def assess_GET_request(self, target_url):
        """
        Assess a GET request for reflection and, if successful, for XSS.
        Supplied argument should have variables in it.

        Args:
            target_url (str)

        Returns:
            (obj)
        """

        output = {}
        output['results'] = {}

        if not self.__is_GET_request_valid(target_url):
            raise RuntimeError('The provided GET request is not valid: ' + target_url)

        if self.do_xss_scanning and not self.do_reflection_checking:
            xss_scan_results = self.__xss_scan_all_GET_params(target_url)
            output = self.__add_xss_results_to_output_obj(output, xss_scan_results)
        else:
            information_from_reflect_check = self.__find_GET_reflected_params(target_url)
            output = self.__add_reflection_results_to_output_obj(output, information_from_reflect_check)

            if len(information_from_reflect_check.params_reflected) > 0 and self.do_xss_scanning:
                xss_scan_results = self.__xss_scan(information_from_reflect_check)
                output = self.__add_xss_results_to_output_obj(output, xss_scan_results)

        return output

    def assess_POST_request(self, target_url, target_body):
        """
        Assess a POST request for reflection and, if successful, for XSS.

        Args:
            target_url (str)
            target_body (str)

        Returns:
            (obj)
        """

        output = {}
        output['results'] = {}

        if not self.__is_POST_request_valid(target_url, target_body):
            err_msg = 'The provided POST request is not valid:\n\tURL: '
            err_msg += target_url + '\n\tBody: ' + target_body
            raise RuntimeError(err_msg)

        if self.do_xss_scanning and not self.do_reflection_checking:
            xss_scan_results = self.__xss_scan_all_POST_params(target_url, target_body)
            output = self.__add_xss_results_to_output_obj(output, xss_scan_results)
        else:
            information_from_reflect_check = self.__find_POST_reflected_params(target_url, target_body)
            output = self.__add_reflection_results_to_output_obj(output, information_from_reflect_check)

            if information_from_reflect_check.params_reflected and self.do_xss_scanning:
                xss_scan_results = self.__xss_scan(information_from_reflect_check)
                output = self.__add_xss_results_to_output_obj(output, xss_scan_results)

        return output

    def __add_xss_results_to_output_obj(self, output, xss_scan_res):
        """
        (Private) Add output/results from XSS scanning to an XssMap output object.

        Args:
            output (obj)
            xss_scan_output (obj)

        Returns:
            (obj)
        """

        output['results']['xss_scan'] = []

        for result in xss_scan_res:
            output['results']['xss_scan'].append(result)

        return output

    def __add_reflection_results_to_output_obj(self, output, reflect_check_res):
        """
        (Private) Add output/results from reflection checking to an XssMap output object.

        Args:
            output (obj)
            reflect_check_output (obj)

        Returns:
            (obj)
        """

        output['request_url_root'] = reflect_check_res.request_url_root
        output['request_type'] = reflect_check_res.request_type

        output['results']['reflection_check'] = {}

        output['results']['reflection_check']['params_reflected'] = reflect_check_res.params_reflected
        output['results']['reflection_check']['params_other'] = reflect_check_res.params_other

        return output

    def __is_GET_request_valid(self, target_url):
        """
        (Private) Assess whether provided GET request URL is of valid format.

        Args:
            target_url (str)

        Returns:
            (bool)
        """

        if target_url is None:
            return False
        elif len(target_url) < 7:
            # http:// alone is 7 chars
            return False

        request_start_pattern = re.compile('^(http|https)://')

        if request_start_pattern.match(target_url) is False:
            return False

        return True

    def __is_POST_request_valid(self, target_url, target_body):
        """
        (Private) Assess whether provided POST request URL and body are of valid format.

        Currently only form-encoded POST bodies are considered valid in XssMap.

        Args:
            target_url (str)
            target_body (str)

        Returns:
            (bool)
        """

        # Leverage URL validation from __is_GET_request_valid...
        if self.__is_GET_request_valid(target_url) is False:
            return False

        # Try to ensure target_body is form-urlencoded, by checking characters against
        # known valid ones
        form_encoded_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234'
        form_encoded_chars += '56789-._~:/?#[]@!$&\'()*+,;=`.%'

        for c in target_body:
            if c not in form_encoded_chars:
                return False

        return True

    def __find_GET_reflected_params(self, target_url):
        """
        (Private) Find reflected params in GET request.

        Args:
            target_url (str)

        Returns:
            (XssMapObject)
        """

        information_from_probe = RequestVariableProbe.probe_GET_request(target_url)

        self.reflection_checker = ReflectionChecker(information_from_probe)
        information_from_reflect_check = self.reflection_checker.run()

        return information_from_reflect_check

    def __find_POST_reflected_params(self, target_url, target_body):
        """
        (Private) Find reflected params in POST request.

        Args:
            target_url (str)
            target_body (str)

        Returns:
            (XssMapObject)
        """

        information_from_probe = RequestVariableProbe.probe_POST_request(target_url, target_body)

        self.reflection_checker = ReflectionChecker(information_from_probe)
        information_from_reflect_check = self.reflection_checker.run()

        return information_from_reflect_check

    def __xss_scan_all_GET_params(self, target_url):
        """
        (Private) Perform XSS scanning on all params in GET request, skipping preliminary
        reflection checking.

        Args:
            target_url (str)

        Returns:
            (list)
        """

        information_from_probe = RequestVariableProbe.probe_GET_request(target_url)

        these_scan_parameters = XssMapObject()

        these_scan_parameters.request_url_root = information_from_probe.request_url_root
        these_scan_parameters.request_type = 'GET'
        these_scan_parameters.params_reflected = []
        these_scan_parameters.params_other = []

        for param in information_from_probe.params_other:
            this_param = {}
            this_param['name'] = param['name']
            this_param['value'] = param['value']
            this_param['reflect_contexts'] = ['general']  # Implemented as wildcard context
            these_scan_parameters.params_reflected.append(this_param)

        return self.__xss_scan(these_scan_parameters)

    def __xss_scan_all_POST_params(self, target_url, target_body):
        """
        (Private) Perform XSS scanning on all params in POST request, skipping preliminary
        reflection checking.

        Args:
            target_url (str)
            target_body (str)

        Returns:
            (list)
        """

        information_from_probe = RequestVariableProbe.probe_POST_request(target_url, target_body)

        these_scan_parameters = XssMapObject()

        these_scan_parameters.request_url_root = information_from_probe.request_url_root
        these_scan_parameters.request_type = 'POST'
        these_scan_parameters.params_reflected = []
        these_scan_parameters.params_other = []

        for param in information_from_probe.params_other:
            this_param = {}
            this_param['name'] = param['name']
            this_param['value'] = param['value']
            this_param['delivery'] = param['delivery']
            this_param['reflect_contexts'] = ['general']  # Implemented as wildcard context
            these_scan_parameters.params_reflected.append(this_param)

        return self.__xss_scan(these_scan_parameters)

    def __xss_scan(self, scan_parameters):
        """
        (Private) Perform an XSS scan with the given parameters.

        Args:
            scan_parameters (XssMapObject)
        """

        self.xss_scanner = XssScanner(scan_parameters)
        scan_results = self.xss_scanner.run()

        return scan_results

# Run from command line
if __name__ == '__main__':

    # Parse input parameters... if something goes awry, the method prints usage
    request_type, request_url, request_body, do_reflect, do_xss, \
            headers, cookies, output_filename = handle_input(JSON_VERSION, sys.argv)

    XSS_MAP = XssMap(do_reflect, do_xss, cookies, headers)
    output_data = {}

    if request_type == 'GET':
        output_data = XSS_MAP.assess_GET_request(request_url)
    elif request_type == 'POST':
        output_data = XSS_MAP.assess_POST_request(request_url, request_body)

    with open(output_filename, 'w') as outfile:
        json.dump(output_data, outfile)
