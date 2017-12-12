# -*- mode: ruby -*-
# vi: set ft=ruby :

##
## This Vagrantfile and its associated scripts provide an environment to running
##   the XSS tool. Setup scripts run the PhantomJS server as a systemd service.
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

# The "2" in Vagrant.configure is the configuration version...
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"

  # Forwarded port mapping between host and guest machines
  config.vm.network "forwarded_port", guest: 80, host: 8080

  # Share folder to the guest VM
  config.vm.synced_folder ".", "/opt/attack-scripts/xss/"

  # Provider-specific configuration
  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM
    vb.memory = "2048"
  end

  # Provisioning via shell scripts
  config.vm.provision "shell", path: "demo-site/demo-site-setup.sh"
  config.vm.provision "shell", path: "install.sh"
end
