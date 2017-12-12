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

class XssMapObject:
    """
    This is an object used throughout XssMap and its minion classes
    RequestVariableProbe (it's the output), ReflectionChecker (it's the
    input and output), and XssScanner (it's the input).

    Below is how it looks coming out of RequestVariableProbe:

        {
            'request_type' : 'GET',
            'request_url_root' : 'http://localhost/basic-xss.php',
            'params_other' :
                [
                    {
                        'delivery' : 'url',
                        'name' : 'param_name',
                        'value' : 'randy',
                        'reflect_trigger' : 'bhjdbhavx'
                    },
                    {
                        'delivery' : 'url',
                        'name' : 'param2',
                        'value' : 'jay',
                        'reflect_trigger' : 'hyqkvtalo'
                    }
                ]
        }

    Below is how it looks going into XssScanner:

        {
            'request_type' : 'GET',
            'request_url_root' : 'http://localhost/basic-xss.php',
            'params_reflected' :
                [
                    {
                        'delivery' : 'url',
                        'name' : 'param_name',
                        'value' : 'randy',
                        'reflect_trigger' : 'bhjdbhavx',
                        'reflect_contexts' : [ 'text' ]
                    }
                ],
            'params_other' :
                [
                    {
                        'delivery' : 'url',
                        'name' : 'param2',
                        'value' : 'jay',
                        'reflect_trigger' : 'nakxyuqmo'
                    }
                ]
        }

    """

    def __init__(self):
        self.request_type = None
        self.request_url_root = None
        self.request_body = None
        self.params_reflected = []
        self.params_other = []
