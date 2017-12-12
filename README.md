# XSS Tool Overview

This tool is an intelligent XSS detection tool that uses human techniques to look for reflected cross-site scripting (XSS) vulnerabilities. 

Rather than use the same approach as virtually every other reflected cross-site scripting tool, this tool does not take a list of known XSS vectors and fuzz its way through the target site. Instead, the tool takes a surgical approach and follows the same process that a human pen tester follows when looking for reflected XSS vulnerabilities. Namely, a typical human tester:
1. Looks at the parameters of a typical web application request (URL parameters, form parameters, headers, etc.);
2. Observes the response to see if any of the parameters are present (a "reflection");
3. If reflected, verifies that the reflection is not a coincidence;
4. Derives the context of the reflection if not a coincidence;
5. Crafts an attack appropriate to that context;
6. Tests to see if the attack is successful.

This XSS tool follows this same process to efficiently identify potential reflected XSS vulnerabilities. Namely, given a valid URL and/or POST body, the tool makes a request to the application. Using XPath queries, the tool determines which (if any) of the parameters are reflected in the application response. If any are reflected, the tool sends another request with a slightly varied input of the reflected parameter to confirm the detected reflection was not a coincidence. We limit the variation to a short random alphanumeric sequence—just enough to offset coincidental reflections. If this modified parameter is still detected as reflected, then the tool can determine the context of the reflection based on the XPath query used to discover it. 

For example, given a URL parameter value of `foo`, an XPath query `//*[@*[contains(.,'foo')]]` identifies locations where the value `foo` is reflected in an HTML attribute. With the context of reflection, the tool can then use an attack based on the HTML attribute context. With this attack crafted, the tool makes a third request to the application via the PhantomJS headless rendering engine. This engine allows us to hook various events that are triggered by our crafted attack when the attack is successful. Using these hooks, the tool can then determine whether or not the crafted attack actually executed.

For convenience, this tool can detect reflection (`run_reflect`) or detect successful XSS attacks (`run_xss`) separately (i.e. execute steps 1-4, execute steps 5-6 above). We refer to these as "reflection detection" and "XSS scan" respectively.

By following this human technique, our tool is able to find XSS vulnerabilities in as little as 3 requests, whereas most XSS tools hammer the target site with hundreds or thousands of requests.

## Prerequisites
The following prerequisites are needed to run this tool. Alternatively, the demo shown later uses a Vagrantfile that installs the prerequisites and a sample target application that has intentional XSS vulnerabilities.

### PhantomJS

The rendering engine the XSS tool is based on requires PhantomJS.

http://phantomjs.org

On Ubuntu: ```sudo apt install phantomjs```

### Python

Besides the rendering engine, the XSS tool is written in Python.

Python 3.x is recommended and matches the development environment of this tool.

There may be backwards compatibility with Python 2.7 but this has not been actively tested.

### virtualenv

This is a Python package used to contain the software and deal with dependencies in an isolated way.

With Python installed, its package manager `pip` should be available.

Installing virtualenv is then as simple as: `pip install virtualenv`

## Setup

```
virtualenv venv

# activate the virtual env
# (windows + powershell)
.\venv\scripts\activate.ps1
# (linux)
source venv/bin/activate

pip install -r requirements.txt
```

Note you'll need to be in the virtualenv ("activated") whenever you run the Python scripts mentioned below.

After you're running files, execute `deactivate` to exit the virtualenv.

## Running the tool

`XssMap.py` is the tool's entry point. Its inputs can be provided with a .json file, or through command line arguments.

### Input: JSON

Make the `/xss` dir your present working directory, then `python <path-to-code>/XssMap.py my_input_parameters.json`

Where `my_input_parameters.json` is a file in the same directory, that could look like this:

```json
{
    "target_url" : "http://127.0.0.1/demo-xss-site.php?html=foo",
    "run_reflect" : true,
    "run_xss" : true,
    "cookies" : [
        {
            "name" : "my_cookie",
            "value" : "chocolate_chip"
        }
    ],
    "headers" : [
        {
            "name" : "my_header",
            "value" : "666"
        }
    ]
}
```

`target_url` (string) is the only required argument.

`run_reflect` (boolean) and `run_xss` (boolean) specify whether that detection engine should run.

`cookies` and `headers` are lists of objects with `name` and `value` fields, which support various types.

The specified cookies and headers will be added to outgoing HTTP requests.

The JSON Schema for the input can be found in `input_schema.json`

### Input: Command line

`XssMap.py url -x|r -c <cookies> -h <headers>`

The `cookies` and `headers` parameters on the command line match those described for JSON above.

`url` is the target and only required argument.

Either `-x` can be used to only run XSS scanning or `-r` to only run reflection checking.

Cookies to add to outgoing HTTP requests can be added like: `-c name1=value1 name2=value2 lastname=lastvalue`

And headers similarly: `-h header1=value1 header2=value2 header3=value3`

### Output

Currently, `XssMap.py` will output results to a JSON file `XssMap_Results_%Y%m%d-%H%M%S.json` plus print to console.

Here's an abridged sample which conveys the format:

```
{
  "request_type": "GET",
  "request_url_root": "http://127.0.0.1/demo-xss-site.php",
  "results": {
    "xss_scan": [
      {
        "attack": "--><script>alert(484777424)</script><!--",
        "certainty": "CERTAIN",
        "message": "Indicated via alert: \"484777424\"",
        "deliver": "url",
        "parameter": "htmlComment"
      },
      {
        "attack": "--><b onmouseover=alert(303035265) >text</b><!--",
        "certainty": "CERTAIN",
        "message": "Indicated via alert: \"303035265\"",
        "deliver": "url",
        "parameter": "htmlComment"
      }
    ],
    "reflection_check": {
      "params_other": [],
      "params_reflected": [
        {
          "delivery": "url",
          "value": "foo",
          "reflect_trigger": "qubutmrue",
          "reflect_contexts": [
            "comment"
          ],
          "name": "htmlComment"
        }
      ]
    }
  }
}
```

The JSON Schema for the output can be found in `output_schema.json`, which explains the output in greater detail. At a high level, the `reflection_check` object lists the reflected parameters and the identified contexts. The `xss_scan` object lists successful attack strings.

# Quick Demo
As a demonstration, a Vagrantfile has been provided that installs the prerequisites and a sample target application that has intentional XSS vulnerabilities. The Vagrantfile forwards port 8080 on your local machine to port 80 on the created virtual machine, meaning you can access the sample target site at http://localhost:8080/demo-site-xss.php

## Prerequisites
In order to execute the quick demo below, Vagrant and VirtualBox must be installed. Installers for these products are available from HashiCorp and Oracle respectively:
* Vagrant (https://www.vagrantup.com/downloads.html)
* VirtualBox (https://www.virtualbox.org/wiki/Downloads)
* An SSH client
 * On Windows, you will also need an SSH client such as PuTTY:
  * Install PuTTY (http://www.chiark.greenend.org.uk/~sgtatham/putty/)
  * Ensure putty.exe and puttygen.exe are on your PATH
  * Assuming Vagrant has already been installed, from a Powershell or cmd type:
    `vagrant plugin install vagrant-multi-putty`

## Instructions
Use the following steps to demo the XSS tool:
1. `vagrant up`
2. `vagrant ssh` (or `vagrant putty` on Windows)
3. `python3 /opt/attack-scripts/xss/XssMap.py /opt/attack-scripts/xss/sample-json/xssmap_single_test_GET_input.json`
4. `cat ~/XssMap_Results_*.json`

