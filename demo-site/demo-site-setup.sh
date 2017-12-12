#!/bin/bash

##
## Distribution script to setup a base Ubuntu VM image for serving up the
##   demo PHP XSS page
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

apt-get update

apt-get install -y apache2 php7.0 libapache2-mod-php7.0

ln -s /opt/attack-scripts/xss/demo-site/demo-xss-site.php /var/www/html/

service apache2 restart
