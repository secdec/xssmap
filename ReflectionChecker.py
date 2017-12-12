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
ReflectionChecker.py
"""

import base64
import json
import random
import re
import string

from lxml import html
import requests

from PageRenderAPI import PageRenderAPI

class ReflectionChecker(object):
    """
    Checks for precursors of cross-site scripting - reflection of parameters into the
    rendered web page.
    """

    def __init__(self, information_from_probe):
        """
        ReflectionChecker is initialized by output from RequestVariableProbe.

        Args:
            information_from_probe (XssMapObject)
        """

        self.data = None
        self.searches = []
        self.request_url = ''
        self.request_body = ''
        self.load(information_from_probe)

        self.headers = {}
        self.cookies = {}

    def add_headers(self, headers):
        """
        Add custom headers to be sent with HTTP requests.

        Args:
            headers (list)
        """

        self.headers = headers

    def add_cookies(self, cookies):
        """
        Add custom cookies to be sent with HTTP requests.

        Args:
            cookies (list)
        """

        self.cookies = cookies

    def load(self, information_from_probe):
        """
        Load information from a RequestVariableProbe output object.

        Args:
            information_from_probe (XssMapObject)
        """

        self.data = information_from_probe
        self.request_url = None

        if self.data.request_type == 'GET':
            self.__load_fields_from_GET()
        elif self.data.request_type == 'POST':
            self.__load_fields_from_POST()
        else:
            self.request_url = self.data.request_url_root

    def __load_fields_from_GET(self):
        """
        (Private) Builds a GET URL that includes the root plus all the needed
        parameters and their generated trigger strings as values, also fills
        in the 'searches' field.
        """

        self.request_url = self.data.request_url_root.split('?', 1)[0]
        self.searches = []

        for idx, param in enumerate(self.data.params_other):
            if idx == 0:
                self.request_url = self.request_url + '?'
            trigger_str = self.__make_trigger()
            self.request_url = self.request_url + param['name']
            self.request_url = self.request_url + '='
            self.request_url = self.request_url + trigger_str
            if idx < len(self.data.params_other) - 1:
                self.request_url = self.request_url + '&'
            self.data.params_other[idx]['reflect_trigger'] = trigger_str
            self.searches.append(trigger_str)

    def __load_fields_from_POST(self):
        """
        (Private) Builds a POST request - URL and body - that includes the root
        plus all the needed parameters and their generated trigger strings as
        values, also fills in the 'searches' field.
        """

        self.request_url = self.data.request_url_root.split('?', 1)[0]
        self.request_body = ''

        self.searches = []

        first_url_param = True

        for idx, param in enumerate(self.data.params_other):
            if param['delivery'] == 'url' and first_url_param is True:
                first_url_param = False
                self.request_url = self.request_url + '?'
            trigger_str = self.__make_trigger()
            if param['delivery'] == 'url':
                self.request_url = self.request_url + param['name']
                self.request_url = self.request_url + '='
                self.request_url = self.request_url + trigger_str
                self.request_url = self.request_url + '&'
            elif param['delivery'] == 'body':
                self.request_body = self.request_body + param['name']
                self.request_body = self.request_body + '='
                self.request_body = self.request_body + trigger_str
                self.request_body = self.request_body + '&'
            else:
                raise RuntimeError('Unrecognized value in "delivery" field of param.')
            self.searches.append(trigger_str)
            self.data.params_other[idx]['reflect_trigger'] = trigger_str

        # Ensure request URL and encoded body do not end with an ampersand
        if self.request_url[-1] == '&':
            self.request_url = self.request_url[:-1]
        if self.request_body and self.request_body[-1] == '&':
            self.request_body = self.request_body[:-1]

    def __find_parameter_and_mark_as_reflected(self, trigger_str):
        """
        (Private) In the stored self.data object, find the 'params_other' entry that has the
        given trigger string, then delete its entry there, add it to 'params_reflected', and
        finally return the index where it lives now.

        Args:
            trigger_str (str)

        Return:
            (int)
        """

        for idx, param in enumerate(self.data.params_other):
            if param['reflect_trigger'] == trigger_str:
                reflected_param = param
                reflected_param['reflect_contexts'] = []
                self.data.params_reflected.append(reflected_param)
                del self.data.params_other[idx]
                return len(self.data.params_reflected) - 1

        raise RuntimeError('Unable to find triggered parameter!')

    def __make_trigger(self):
        """
        (Private) Generate trigger string - 9 random lowercase alpha chars.

        Returns:
            (str)
        """

        return ''.join(random.choice(string.ascii_lowercase) for i in range(9))

    def __get_and_prepare_request_inputs(self):
        """
        (Private) Returns an object that can be sent to a rendering
        engine to get rendered page output.

        Returns:
            (obj)
        """

        if self.data.request_type == 'POST':
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        inputs = {}
        inputs['method'] = self.data.request_type
        inputs['url'] = base64.b64encode(bytes(self.request_url, 'utf-8'))
        if self.request_body != '':
            inputs['body'] = base64.b64encode(bytes(self.request_body, 'utf-8'))
        if self.headers:
            inputs['headers'] = base64.b64encode(bytes(json.dumps(self.headers), 'utf-8'))
        if self.cookies:
            inputs['cookies'] = base64.b64encode(bytes(json.dumps(self.cookies), 'utf-8'))

        return inputs

    def __analyze_rendered_page_output(self, rendered_page_output):
        """
        (Private) Check for indicators of reflection in a rendered page
        output object and return results.

        Args:
            rendered_page_output (obj)

            {
                'page_html' : string of page's rendered html
                'page_errors' : list of strings of javascript error()
                'page_console_messages' : list of strings of javascript console.log()
                'page_confirms' : list of strings of javascript confirm()
                'page_prompts' : list of strings of javascript prompt()
            }

        Returns:
            (list)
        """

        page_html_tree = html.fromstring(rendered_page_output['page_html'])

        results = []

        for search in self.searches:
            result = {}
            result['payload'] = search
            result['contexts'] = []

            # node with search string
            nn_xpath = '//' + search
            nn = page_html_tree.xpath(nn_xpath)
            nn_count = len(nn)

            if nn_count:
                context = {}
                context['type'] = 'nodename'
                context['count'] = nn_count
                result['contexts'].append(context)

            # attribute name //*[ . = "val"]
            an_xpath = '//*[@' + search + ']'
            an = page_html_tree.xpath(an_xpath)
            an_count = len(an)

            if an_count:
                context = {}
                context['type'] = 'attributename'
                context['count'] = an_count
                result['contexts'].append(context)

            # attribute value
            av_xpath = '//*[@*[contains(.,\'' + search + '\')]]'
            av = page_html_tree.xpath(av_xpath)
            av_count = len(av)

            if av_count:
                context = {}
                context['type'] = 'attributevalue'
                context['count'] = av_count
                result['contexts'].append(context)

            # text value
            tv_xpath = '//*[contains(text(),\'' + search + '\')]'
            tv = page_html_tree.xpath(tv_xpath)
            tv_count = len(tv)

            if tv_count:
                context = {}
                context['type'] = 'text'
                context['count'] = tv_count
                result['contexts'].append(context)

            # html comment
            com_xpath = '//*[comment()[contains(.,\'' + search + '\')]]'
            com = page_html_tree.xpath(com_xpath)
            com_count = len(com)

            if com_count:
                context = {}
                context['type'] = 'comment'
                context['count'] = com_count
                result['contexts'].append(context)

            # ** Special instances of the above... **

            # <style>
            style_xpath = '//style[contains(text(),\'' + search + '\')]'
            style = page_html_tree.xpath(style_xpath)
            style_count = len(style)

            if style_count:
                context = {}
                context['type'] = 'style'
                context['count'] = style_count
                result['contexts'].append(context)

            # inside id attribute value
            idattrib_xpath = '//*[@id[contains(.,\'' + search + '\')]]'
            idattrib = page_html_tree.xpath(idattrib_xpath)
            idattrib_count = len(idattrib)

            if idattrib_count:
                context = {}
                context['type'] = 'idattrib'
                context['count'] = idattrib_count
                result['contexts'].append(context)

            # inside class attribute value
            clazz_xpath = '//*[@class[contains(.,\'' + search + '\')]]'
            clazz = page_html_tree.xpath(clazz_xpath)
            clazz_count = len(clazz)

            if clazz_count:
                context = {}
                context['type'] = 'classattrib'
                context['count'] = clazz_count
                result['contexts'].append(context)

            # inside style attribute value
            styleattrib_xpath = '//*[@style[contains(.,\'' + search + '\')]]'
            styleattrib = page_html_tree.xpath(styleattrib_xpath)
            styleattrib_count = len(styleattrib)

            if styleattrib_count:
                context = {}
                context['type'] = 'styleattrib'
                context['count'] = styleattrib_count
                result['contexts'].append(context)

            # ** Harder ones... Javascript **

            # inside <script> header
            jsnode_xpath = '//script[contains(text(),\'' + search + '\')]'
            jsnode = page_html_tree.xpath(jsnode_xpath)
            jsnode_count = len(jsnode)

            if jsnode_count:
                context = {}
                context['type'] = 'jsnode'
                context['count'] = jsnode_count
                result['contexts'].append(context)

            # each instance of <script> comes out differently, parse each for content

            jssqcount = 0
            jsdqcount = 0
            js_xpath = '//script[contains(text(),\'' + search + '\')]'
            js = page_html_tree.xpath(js_xpath)

            for js_finding in js:
                js_string = js_finding.text

                # TODO below line is a mix of Javascript and Python, implement for some rare cases...
                #escaped_search = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

                sqre = re.compile('\'(?:[^\'\\\\]|\\\\.)*' + search + '(?:[^\'\\\\]|\\\\.)*\'')
                #sqre = re.compile('\'(?:[^\'\\\\]|\\\\.)*' + escaped_search + '(?:[^\'\\\\]|\\\\.)*\'')
                dqre = re.compile('"(?:[^"\\\\]|\\\\.)*' + search + '(?:[^"\\\\]|\\\\.)*"')
                #dqre = re.compile('(?:[^"\\\\]|\\\\.)*' + escaped_search + '(?:[^"\\\\]|\\\\.)*"')

                sq = sqre.findall(js_string)
                dq = dqre.findall(js_string)

                jssqcount += len(sq)
                jsdqcount += len(dq)

            if jssqcount:
                context = {}
                context['type'] = 'jssinglequote'
                context['count'] = jssqcount
                result['contexts'].append(context)

            if jsdqcount:
                context = {}
                context['type'] = 'jsdoublequote'
                context['count'] = jsdqcount
                result['contexts'].append(context)

            # inside any onXXXX() attribute
            onattrib_xpath = '//*[@onerror[contains(.,\'' + search \
                    + '\')] or @onload[contains(.,\'' + search \
                    + '\')] or @onclick[contains(.,\'' + search \
                    + '\')] or @oncontextmenu[contains(.,\'' + search \
                    + '\')] or @ondblclick[contains(.,\'' + search \
                    + '\')] or @onmousedown[contains(.,\'' + search \
                    + '\')] or @onmouseenter[contains(.,\'' + search \
                    + '\')] or @onmouseleave[contains(.,\'' + search \
                    + '\')] or @onmousemove[contains(.,\'' + search \
                    + '\')] or @onmouseover[contains(.,\'' + search \
                    + '\')] or @onmouseout[contains(.,\'' + search \
                    + '\')] or @onmouseup[contains(.,\'' + search \
                    + '\')] or @onkeydown[contains(.,\'' + search \
                    + '\')] or @onkeypress[contains(.,\'' + search \
                    + '\')] or @onkeyup[contains(.,\'' + search \
                    + '\')] or @onabort[contains(.,\'' + search \
                    + '\')] or @onbeforeunload[contains(.,\'' + search \
                    + '\')] or @onhashchange[contains(.,\'' + search \
                    + '\')] or @onpageshow[contains(.,\'' + search \
                    + '\')] or @onpagehide[contains(.,\'' + search \
                    + '\')] or @onresize[contains(.,\'' + search \
                    + '\')] or @onscroll[contains(.,\'' + search \
                    + '\')] or @onunload[contains(.,\'' + search \
                    + '\')] or @onblur[contains(.,\'' + search \
                    + '\')] or @onchange[contains(.,\'' + search \
                    + '\')] or @onfocus[contains(.,\'' + search \
                    + '\')] or @onfocusin[contains(.,\'' + search \
                    + '\')] or @onfocusout[contains(.,\'' + search \
                    + '\')] or @oninput[contains(.,\'' + search \
                    + '\')] or @oninvalid[contains(.,\'' + search \
                    + '\')] or @onreset[contains(.,\'' + search \
                    + '\')] or @onsearch[contains(.,\'' + search \
                    + '\')] or @onselect[contains(.,\'' + search \
                    + '\')] or @ondrag[contains(.,\'' + search \
                    + '\')] or @ondragend[contains(.,\'' + search \
                    + '\')] or @ondragenter[contains(.,\'' + search \
                    + '\')] or @ondragleave[contains(.,\'' + search \
                    + '\')] or @ondragover[contains(.,\'' + search \
                    + '\')] or @ondragstart[contains(.,\'' + search \
                    + '\')] or @ondrop[contains(.,\'' + search \
                    + '\')] or @oncopy[contains(.,\'' + search \
                    + '\')] or @oncut[contains(.,\'' + search \
                    + '\')] or @onpaste[contains(.,\'' + search \
                    + '\')] or @onafterprint[contains(.,\'' + search \
                    + '\')] or @onbeforeprint[contains(.,\'' + search \
                    + '\')] or @onabort[contains(.,\'' + search \
                    + '\')] or @oncanplay[contains(.,\'' + search \
                    + '\')] or @oncanplaythrough[contains(.,\'' + search \
                    + '\')] or @ondurationchange[contains(.,\'' + search \
                    + '\')] or @onemptied[contains(.,\'' + search \
                    + '\')] or @onended[contains(.,\'' + search \
                    + '\')] or @onloadeddata[contains(.,\'' + search \
                    + '\')] or @onloadedmetadata[contains(.,\'' + search \
                    + '\')] or @onloadstart[contains(.,\'' + search \
                    + '\')] or @onpause[contains(.,\'' + search \
                    + '\')] or @onplay[contains(.,\'' + search \
                    + '\')] or @onplaying[contains(.,\'' + search \
                    + '\')] or @onprogress[contains(.,\'' + search \
                    + '\')] or @onratechange[contains(.,\'' + search \
                    + '\')] or @onseeked[contains(.,\'' + search \
                    + '\')] or @onseeking[contains(.,\'' + search \
                    + '\')] or @onstalled[contains(.,\'' + search \
                    + '\')] or @onsuspend[contains(.,\'' + search \
                    + '\')] or @ontimeupdate[contains(.,\'' + search \
                    + '\')] or @onvolumechange[contains(.,\'' + search \
                    + '\')] or @onwaiting[contains(.,\'' + search \
                    + '\')] or @onopen[contains(.,\'' + search \
                    + '\')] or @onmessage[contains(.,\'' + search \
                    + '\')] or @onmousewheel[contains(.,\'' + search \
                    + '\')] or @ononline[contains(.,\'' + search \
                    + '\')] or @onoffline[contains(.,\'' + search \
                    + '\')] or @onpopstate[contains(.,\'' + search \
                    + '\')] or @onshow[contains(.,\'' + search \
                    + '\')] or @onstorage[contains(.,\'' + search \
                    + '\')] or @ontoggle[contains(.,\'' + search \
                    + '\')] or @onwheel[contains(.,\'' + search \
                    + '\')] or @ontouchcancel[contains(.,\'' + search \
                    + '\')] or @ontouchend[contains(.,\'' + search \
                    + '\')] or @ontouchmove[contains(.,\'' + search \
                    + '\')] or @ontouchstart[contains(.,\'' + search \
                    + '\')] or @onsubmit[contains(.,\'' + search + '\')]]'
            onattrib = page_html_tree.xpath(onattrib_xpath)
            onattrib_count = len(onattrib)

            if onattrib_count:
                context = {}
                context['type'] = 'onattrib'
                context['count'] = onattrib_count
                result['contexts'].append(context)

            # JS errors
            error_count = 0
            for error_popup in rendered_page_output['page_errors']:
                if search in error_popup:
                    error_count += 1

            if error_count:
                context = {}
                context['type'] = 'js_error'
                context['count'] = error_count
                result['contexts'].append(context)

            # JS console messages
            console_msg_count = 0
            for console_msg in rendered_page_output['page_console_messages']:
                if search in console_msg:
                    console_msg_count += 1

            if console_msg_count:
                context = {}
                context['type'] = 'js_console'
                context['count'] = console_msg_count
                result['contexts'].append(context)

            # prompt() popups
            prompt_popup_count = 0
            for prompt_popup in rendered_page_output['page_prompts']:
                if search in prompt_popup:
                    prompt_popup_count += 1

            if prompt_popup_count:
                context = {}
                context['type'] = 'js_prompt'
                context['count'] = prompt_popup_count
                result['contexts'].append(context)

            # confirm() popups
            confirm_popup_count = 0
            for confirm_popup in rendered_page_output['page_confirms']:
                if search in confirm_popup:
                    confirm_popup_count += 1

            if confirm_popup_count:
                context = {}
                context['type'] = 'js_confirm'
                context['count'] = confirm_popup_count
                result['contexts'].append(context)

            if result['contexts']:
                results.append(result)

        return results

    def run(self):
        """
        Run main functionality.

        Returns:
            (XssMapObject)
        """

        rendered_page_output = PageRenderAPI.render_page_with_phantom(self.data.request_type, \
                    self.request_url, self.request_body, self.headers, self.cookies)

        results = self.__analyze_rendered_page_output(rendered_page_output)

        self.data.params_reflected = []

        if results:
            for result in results:
                index = self.__find_parameter_and_mark_as_reflected(result['payload'])
                for context in result['contexts']:
                    context_desc = context['type']
                    self.data.params_reflected[index]['reflect_contexts'].append(context_desc)
        else:
            # TODO could try Slimer engine, or another Javascript engine
            pass

        return self.data
