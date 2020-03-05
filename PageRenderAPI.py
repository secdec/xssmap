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
PageRenderAPI.py
"""

import base64
import json
import socket

import requests

from XssMapSettings import PHANTOM_ADDRESS

class PageRenderAPI(object):
    """
    Handles requests to XssMap's various Javascript engines,
    returning rendered page data for analysis.
    """

    @staticmethod
    def ensure_local_service_is_up(name, address):
        """
        Checks if a local rendering service is up, error out if not.

        Args:
            name (str) - name of service
            address (str) - where to check for service
        """

        service_port = int(''.join(c for c in address.split(':')[-1] if c.isdigit()))
        service_up = False

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            test_socket.bind(('127.0.0.1', service_port))
            test_socket.close()
        except socket.error:
            # Could not bind to port, assume service is up there
            service_up = True

        if not service_up:
            msg = name + ' does not seem to be running at ' + address
            raise RuntimeError(msg)

    @staticmethod
    def render_page_with_phantom(method, url, body, headers, cookies, pageEvents=False):
        """
        Send request parameters to PhantomJS engine and get rendered page output.

        Returns:
            (obj)

            {
                'page_html' : string of page's rendered html
                'page_errors' : list of strings of javascript error()
                'page_console_message' : list of strings of javascript console.log()
                'page_confirms' : list of strings of javascript confirm()
                'page_prompts' : list of strings of javascript prompt()
            }
        """

        u = 'utf-8'

        inputs = {}

        inputs['method'] = method
        inputs['url'] = base64.b64encode(bytes(url, u))

        if body and body != '':
            inputs['body'] = base64.b64encode(bytes(body, u))

        if headers or method == 'POST':
            if not headers:
                inputs['headers'] = {}
            else:
                inputs['headers'] = headers
            if method == 'POST':
                inputs['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
            inputs['headers'] = base64.b64encode(bytes(json.dumps(inputs['headers']), u))

        if cookies:
            inputs['cookies'] = base64.b64encode(bytes(json.dumps(cookies), u))

        inputs['provokePageEvents'] = True

        if '127.0.0.1' in PHANTOM_ADDRESS or 'localhost' in PHANTOM_ADDRESS:
            PageRenderAPI.ensure_local_service_is_up('PhantomJS rendering engine', PHANTOM_ADDRESS)

        r = requests.post(PHANTOM_ADDRESS, data=inputs)
        r.connection.close()

        rendered_page_output = r.json()

        output = {}

        try:
          page_html = base64.b64decode(rendered_page_output['html']).decode(u)
        except UnicodeDecodeError as e:
          page_html = base64.decodebytes(bytes(rendered_page_output['html'], u))
        output['page_html'] = page_html

        page_errors = base64.b64decode(rendered_page_output['errors']).decode(u)
        page_errors = json.loads(page_errors)
        output['page_errors'] = page_errors

        page_console_msgs = base64.b64decode(rendered_page_output['consoleMessages']).decode(u)
        page_console_msgs = json.loads(page_console_msgs)
        output['page_console_messages'] = page_console_msgs

        page_alerts = base64.b64decode(rendered_page_output['alerts']).decode(u)
        page_alerts = json.loads(page_alerts)
        output['page_alerts'] = page_alerts

        page_confirms = base64.b64decode(rendered_page_output['confirms']).decode(u)
        page_confirms = json.loads(page_confirms)
        output['page_confirms'] = page_confirms

        page_prompts = base64.b64decode(rendered_page_output['prompts']).decode(u)
        page_prompts = json.loads(page_prompts)
        output['page_prompts'] = page_prompts

        return output
