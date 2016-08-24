#!/bin/bash
source bin/activate
LOG=reset.log
>${LOG}
pip uninstall PyBeacon -y >${LOG} $2>&1;
if [[ -f local_config.yml ]]; then
  LOCALCONFIG=true
  echo 'backing up local_config'
  cp local_config.yml /tmp/
fi

git clean -df >>${LOG} $2>&1
git reset --hard >>${LOG} $2>&1
if [[ $(git branch |grep -c foo) -gt 0 ]]; then
  git branch -D foo >>${LOG} $2>&1
fi
git branch foo

if [[ `grep -q 'hcidump' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcidump commands still running. killing them."
    sudo killall hcidump
fi
if [[ `grep -q 'hcitool' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcitool commands still running. killing them."
    sudo killall hcitool
fi
>/var/log/pybeacon.log
git checkout foo >>${LOG} $2>&1 && git reset --hard >>${LOG} $2>&1 &&
git branch -D master
git fetch ; git checkout master
echo 'Creating virtualenv'
virtualenv --python=python3 ../PyBeacon >>${LOG} $2>&1 &&
echo 'Settin up PyBeacon'
. bin/activate >>${LOG} $2>&1 && pip install -r requirements.txt >>${LOG} $2>&1 &&
echo 'Pip'
pip install . >>${LOG} $2>&1
if [[ $LOCALCONFIG == true ]]; then
    echo "restoring local config"
    cp /tmp/local_config.yml .
fi
echo 'sleeping for 2 seconds to give you time to interrupt me before I start PyBeacon'
sleep 1
echo 'just kidding. too slow charlie.'
PyBeacon -s
