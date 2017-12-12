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
CommandLineUtils.py

XssMap.py command line input utilities, including JSON config file parsing
and traditional argument parsing
"""

import json
import time

def __print_command_line_usage():
    """
    (Private) Print XssMap.py command line usage
    """

    print('usage : python XssMap.py myparams.json outputname.json')
    print('   inputs "json_version" (float, currently 1.00 supported),')
    print('          "request_type" (str), request_url" (str),')
    print('          "request_type" (str), "do_reflect" (bool),')
    print('          "do_xss" (bool),')
    print('          "headers" (list of objects with "name" and "value" fields),')
    print('          "cookies" (list of objects with "name" and "value" fields)')
    print('OR can use command line args for GET request targets only')
    print(' python XssMap.py url -x|r -c <cookies> -h <headers>')
    print('     url : target url, all arguments after this are optional...')
    print('     -t : put request type after, default is "GET", can also "POST"')
    print('     -b : put request body string after')
    print('     -x : only do xss scanning')
    print('     -r : only do reflection checking')
    print('     -h : put headers after, like header1=value1 header2=value2')
    print('     -c : put cookies after, like cookie1=value1 cookie2=value2')
    exit()

def __parse_json_input(json_version, arg_array):
    """
    (Private) Parses XssMap.py input / startup params from a JSON file.

    Args:
        json_version (float)
        arg_array (list)

    Returns:
        request_type (str)
        request_url (str)
        request_body (str)
        do_reflect (bool)
        do_xss (bool)
        headers (list)
        cookies (list)
    """

    request_type = 'GET'
    request_url = None
    request_body = None
    do_reflect = True
    do_xss = True
    headers = []
    cookies = []

    with open(arg_array[1]) as json_data:

        d = json.load(json_data)

        if 'json_version' in d:
            if d['json_version'] != json_version:
                raise RuntimeError('Supported JSON version is ' + str(json_version))

        if 'request_type' in d:
            request_type = d['request_type']

        # This is the one param we really require
        if 'request_url' in d:
            request_url = d['request_url']
        else:
            raise RuntimeError('Missing "request_url" param field in JSON config file.')

        if 'request_body' in d:
            request_body = d['request_body']

        if 'do_reflect' in d:
            do_reflect = d['do_reflect']

        if 'do_xss' in d:
            do_xss = d['do_xss']

        if 'headers' in d:
            for header_dump in d['headers']:
                header_name = header_dump['name']
                header_val = header_dump['value']
                header = header_name, header_val
                headers.append(header)

        if 'cookies' in d:
            for cookie_dump in d['cookies']:
                cookie_name = cookie_dump['name']
                cookie_val = cookie_dump['value']
                cookie = cookie_name, cookie_val
                cookies.append(cookie)

    return request_type, request_url, request_body, do_reflect, do_xss, headers, cookies

def __parse_cli_input(arg_array):
    """
    (Private) Parses XssMap.py input / startup params from command line args.

    Args:
        arg_array (list)

    Returns:
        request_type (str)
        request_url (str)
        request_body (str)
        do_reflect (bool)
        do_xss (bool)
        headers (list)
        cookies (list)
    """

    request_type = 'GET'
    request_url = None
    request_body = None
    do_reflect = True
    do_xss = True
    cookies = []
    headers = []

    idx = 1
    while idx < len(arg_array):
        arg = arg_array[idx]
        if idx == 1:
            request_url = arg_array[1]
            idx = idx + 1
        elif arg.lower() == '-v':
            # If we encounter verbose flag, ignore for now
            pass
        elif arg.lower() == '-r':
            do_xss = False
            idx = idx + 1
        elif arg.lower() == '-x':
            do_reflect = False
            idx = idx + 1
        elif arg.lower() == '-c':
            idx = idx + 1
            while idx < len(arg_array) and '=' in arg_array[idx]:
                cookie_dump = arg_array[idx].split('=')
                cookies[cookie_dump[0]] = cookie_dump[1]
                idx = idx + 1
        elif arg.lower() == '-h':
            idx = idx + 1
            while idx < len(arg_array) and '=' in arg_array[idx]:
                header_dump = arg_array[idx].split('=')
                headers[header_dump[0]] = header_dump[1]
                idx = idx + 1
        else:
            __print_command_line_usage()

    return request_type, request_url, request_body, do_reflect, do_xss, headers, cookies

def handle_input(json_version, arg_array):
    """
    General method that handles command line input to XssMap.py, interpreting
    either traditional arguments or a JSON input file as needed.

    Args:
        json_version (float)
        arg_array (list)

    Returns:
        request_type (str)
        request_url (str)
        request_body (str)
        do_reflect (bool)
        do_xss (bool)
        headers (list)
        cookies (list)
        output_filename (str)
    """

    # TEMPORARY: delete verbose flag -v
    if len(arg_array) > 1 and arg_array[1].lower() == '-v':
        del arg_array[1]

    # sanity check on command line input
    if len(arg_array) > 1 and arg_array[1].lower() != '-h' and arg_array[1].lower() != '--help':

        interpreted_params = None
        output_filename = 'XssMap_Results_' + time.strftime('%Y%m%d-%H%M%S') + '.json'

        if len(arg_array) >= 2 and ('.json' in arg_array[1].lower()\
                or '.conf' in arg_array[1].lower()):
            # parameters are coming in a .json file... this scenario calls for 3
            # "arguments", where the first is XssMap.py, second is JSON input,
            # third is destination for JSON output file
            interpreted_params = __parse_json_input(json_version, arg_array)

            if len(arg_array) == 3 and ('.json' in arg_array[2].lower()\
                    or '.txt' in arg_array[2].lower()):
                output_filename = arg_array[2]
        else:
            # parameters were given on the command line
            interpreted_params = __parse_cli_input(arg_array)

        return interpreted_params + (output_filename,)

    else:
        # something went awry, print usage
        __print_command_line_usage()
