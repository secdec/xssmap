#!/usr/local/bin/python

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
RequestVariableProbe.py
"""

from XssMapObject import XssMapObject

class RequestVariableProbe(object):
    """
    Isolates parameters from HTTP requests that can be probed with reflection checking
    or XSS scanning.
    """

    @staticmethod
    def __has_URL_params(url):
        """
        (Private) Checks if provided URL has parameters in it.

        Args:
            url (str)

        Returns:
            (bool)
        """

        if '?' not in url:
            return False

        return True

    @staticmethod
    def __process_URL_params(url):
        """
        (Private) Processes a URL, returning a list of param objects based on its content.

        Args:
            url (str)

        Returns:
            (list)
        """

        output_list = []
        params_dump = url.split('?', 1)[1]

        # split on the '&' chars
        originals = params_dump.split('&')

        for orig in originals:

            this_param = {}

            this_param['delivery'] = 'url'

            # for each, split again on '='
            this_param['name'] = orig.split('=', 1)[0]
            this_param['value'] = orig.split('=', 1)[1]

            output_list.append(this_param)

        return output_list

    @staticmethod
    def __process_body_params(body):
        """
        (Private) Processes a request body (URL form-encoded), returning a list of param objects
        based on its content.

        Args:
            body (str)
        """

        output_list = []

        # Note: making a big assumption that this request body is already URL form-encoded and
        # therefore can split on the ampersands

        originals = body.split('&')

        for orig in originals:

            this_param = {}

            this_param['delivery'] = 'body'

            # for each, split again on '='
            this_param['name'] = orig.split('=', 1)[0]
            this_param['value'] = orig.split('=', 1)[1]

            output_list.append(this_param)

        return output_list

    @staticmethod
    def probe_POST_request(original_POST_url, original_POST_body):
        """
        Probe POST request for parameters.

        Args:
            original_POST_url (str)
            original_POST_body (str)

        Returns:
            (XssMapObject)
        """

        output = XssMapObject()
        output.request_url_root = original_POST_url.split('?', 1)[0]
        output.request_type = 'POST'
        output.params_other = []

        # Though it's a POST, maybe there are params in the URL to identify
        if RequestVariableProbe.__has_URL_params(original_POST_url):
            output.params_other = RequestVariableProbe.__process_URL_params(original_POST_url)

        body_params = RequestVariableProbe.__process_body_params(original_POST_body)
        for param in body_params:
            output.params_other.append(param)

        return output

    @staticmethod
    def probe_GET_request(original_GET_url):
        """
        Probe GET request for parameters.

        Args:
            original_GET_request (str)

        Returns:
            (XssMapObject)
        """

        output = XssMapObject()
        output.request_url_root = original_GET_url.split('?', 1)[0]
        output.request_type = 'GET'
        output.params_other = []

        if RequestVariableProbe.__has_URL_params(original_GET_url):
            output.params_other = RequestVariableProbe.__process_URL_params(original_GET_url)

        return output
