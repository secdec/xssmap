//
// This script sets up a PhantonJS server for use by the XSS tool
//
// Application Security Threat Attack Modeling (ASTAM)
//
// Copyright (C) 2017 Applied Visions - http://securedecisions.com
//
// Written by Aspect Security - http://aspectsecurity.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

var fs = require('fs');
var system = require('system');
var webpage = require('webpage');
var webserver = require('webserver');

var host = '127.0.0.1';
var port = '8888';

var server = webserver.create();

console.log('[INFO] Starting PhantomJS rendering engine on ' + host + ':' + port);

var requestCounter = 1;

// Start rendering engine, listen for requests to fulfill
var service = server.listen(host + ':' + port, function(request, response)
{
	if (request.method == 'POST')
	{
		console.log('[DEBUG] Got request ' + requestCounter);
		requestCounter++;

		var url = atob(request.post['url']);

		var method = 'GET';
		if (request.post.hasOwnProperty('method')) {
			method = request.post['method'];
		}

		console.log('[DEBUG] method: ' + method);
		console.log('[DEBUG] url: ' + url);

		var body = null;
		if (request.post.hasOwnProperty('body')) {
			body = atob(request.post['body']);
		}

		console.log('[DEBUG] body: ');
		console.log('[DEBUG] \t' + body);

		var headers = null;
		if (request.post.hasOwnProperty('headers')) {
			headers = JSON.parse(atob(request.post['headers']));
		}

		console.log('[DEBUG] headers: ');
		console.log('[DEBUG] \t' + headers);

		var cookies = null;
		if (request.post.hasOwnProperty('cookies')) {
			cookies = JSON.parse(atob(request.post['cookies']));
		}

		console.log('[DEBUG] cookies: ');
		console.log('[DEBUG] \t' + cookies);

		var provokePageEvents = false;
		if (request.post.hasOwnProperty('provokePageEvents')) {
			provokePageEvents = request.post['provokePageEvents'];
		}

		console.log('[DEBUG] provokePageEvents: ' + provokePageEvents);

		var errors = [];
		var consoleMessages = [];
		var alerts = [];
		var confirms = [];
		var prompts = [];

		var page = webpage.create();

		// Play fast and loose with security settings
		page.settings.javascriptEnabled = true;
		page.settings.loadImages = true;
		page.settings.localToRemoteUrlAccessEnabled = true;
		page.settings.webSecurityEnabled = false;
		page.settings.XSSAuditingEnabled = false;

		page.onError = function(message) {
			errors.push(message);
		};

		page.onConsoleMessage = function(message) {
			consoleMessages.push(message);
		};

		page.onAlert = function(message) {
			alerts.push(message);
		};

		page.onConfirm = function(message) {
			confirms.push(message);
		};

		page.onPrompt = function(message) {
			prompts.push(message);
		};

		if (headers != null) {
			page.customHeaders = headers;
		}

		if (cookies != null) {
			for (var i = 0; i < cookies.length; i++) {
				phantom.addCookie(cookies[i]);
			}
		}

		if (method === 'GET')
		{
			page.open(url, {encoding: 'utf-8'});
		}
		else if (method === 'POST')
		{
			if (body == null)
			{
				body = '';
			}

			//page.open(url, method, body);
			page.open(url, {operation: 'post', data: body, encoding: 'utf-8'});
		}

		page.onLoadFinished = function(status)
		{
			console.log('[DEBUG] Page load finished');

			if (provokePageEvents)
			{
				console.log('[DEBUG] Starting page events');

				// Attempt to hit on all document event handling
				page.evaluate(function()
				{
					var mouseEvents = ['click', 'contextmenu', 'dblclick', 'mousedown',
															'mouseenter', 'mouseleave', 'mousemove',
															'mouseover', 'mouseout', 'mouseup'];

					mouseEvents.forEach(function(mouseEvent) {
						// Match all elements with a handler matching this event
					  var elementsWithNonNullHandlers = document.querySelectorAll("*[on" + mouseEvent + "]");
					  if (elementsWithNonNullHandlers != null ) {
					      elementsWithNonNullHandlers.forEach(function(element) {
									// create the trigger event
									var triggerEvent = new MouseEvent(mouseEvent, {
										bubbles: true,
										cancelable: true,
										view: window
									});

									// dispatch it
									element.dispatchEvent(triggerEvent);
					      });
					  }
					});
				});

				console.log('[DEBUG] Finished page events');
			}

			var res = {};
			console.log('\n\n');
			console.log('[DEBUG] Dumping interpreted page.content \n\n');
			console.log(page.content);
			console.log('\n\n');
			res.html = btoa(page.content);
			res.errors = btoa(JSON.stringify(errors));
			res.consoleMessages = btoa(JSON.stringify(consoleMessages));
			res.alerts = btoa(JSON.stringify(alerts));
			res.confirms = btoa(JSON.stringify(confirms));
			res.prompts = btoa(JSON.stringify(prompts));

			console.log('[DEBUG] End of render, sending response');

			response.statusCode = 200;
			response.write(JSON.stringify(res));
			response.close();

			page.close();
		}
	}
});
