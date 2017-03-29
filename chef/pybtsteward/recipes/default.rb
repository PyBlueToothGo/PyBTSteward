#
# Cookbook Name:: pybtsteward
# Recipe:: default
#
# Copyright 2016, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#
useradd pybtsteward -c 'Bluetooth Steward'
usermod -aG bluetooth pybtsteward
usermod pybtsteward -d /usr/local/PyBTSteward
mkdir /usr/local/PyBTSteward&& chown pybtsteward:bluetooth /usr/local/PyBTSteward
echo "deb https://dl.bintray.com/wolfspyre/rpiBluez jessie main" | sudo tee -a /etc/apt/sources.list
apt-get update
apt-get install screen
apt-get install bluez-firmware bluetooth bluez bluez-hcidump bluez-test-scripts libbluetooth-dev libbluetooth3
systemctl daemon-reload
systemctl enable bluetooth
su - pybtsteward
git clone https://github.com/wolfspyre/PyBTSteward.git
virtualenv --python=python3 PyBTSteward/
. PyBTSteward/bin/activate
 pip install -r requirements.txt
#add config here
#make logfile
root@GrumpysBoombox:~# touch /var/log/pybtsteward.log
root@GrumpysBoombox:~# chmod a+rw /var/log/pybtsteward.log
 pip install .
 give user ability to sudo commands
 #add to sudoers

 Cmnd_Alias BLUETOOTHERY = /bin/hciconfig, /usr/bin/hcitool, /usr/bin/hcidump
 Cmnd_Alias KILL = /bin/kill
 User_Alias BTUSERS = pi,pybtsteward

 BTUSERS ALL=NOPASSWD: BLUETOOTHERY, killall


# seems sufficient to just add:
# %bluetooth ALL=NOPASSWD: /bin/hciconfig, /usr/bin/hcitool, /usr/bin/hcidump, /usr/bin/killall, /bin/kill, /usr/sbin/service

 include_recipe 'fake::default'

 sudo 'pybtsteward' do
   user            'alice'
   command_aliases [{ name: 'BLUETOOTHERY', command_list: ['/bin/hciconfig', '/usr/bin/hcitool', '/usr/bin/hcidump'] }, { name: 'KILL', command_list: ['/bin/kill', '/usr/bin/killall', '/usr/sbin/service'] }]
   commands        ['BLUETOOTHERY','KILL']
   passwordless    true
 end


 #add service
