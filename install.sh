#!/bin/bash

##
## Installation script for prerequisites for running the XSS tool
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

topDir=`dirname "$0"`

# install python etc.

apt-get update
apt-get install -y python3 python3-pip

apt-get install -y phantomjs
## Ubuntu repo version needs to work around QT
echo "export QT_QPA_PLATFORM=offscreen" >> /etc/environment

## Alternatively, install and compile directly from source
# apt-get install -y build-essential g++ flex bison gperf ruby perl libsqlite3-dev libfontconfig1-dev libicu-dev libfreetype6 libssl-dev libpng-dev libjpeg-dev python libx11-dev libxext-dev git
#
# git clone git://github.com/ariya/phantomjs.git
# cd phantomjs
# git checkout 2.1.1
# git submodule init
# git submodule update
#
# python build.py


pip3 install --upgrade pip
pip3 install virtualenv

pip3 install -r /opt/attack-scripts/xss/requirements.txt


## create xss user
useradd -m --system phantomjsd

cat << EOF > /etc/systemd/system/phantomjsd.service

[Unit]
Description=PhantomJS XSS Service
After=network.target

[Service]
Type=simple
User=phantomjsd
WorkingDirectory=/usr/bin/
ExecStart=/usr/bin/phantomjs /opt/attack-scripts/xss/phantom-render.js
Environment=QT_QPA_PLATFORM=offscreen
Restart=always
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

# start the xssd service
systemctl daemon-reload
systemctl enable phantomjsd
systemctl start phantomjsd
