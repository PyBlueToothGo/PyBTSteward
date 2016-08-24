#!/bin/bash
source bin/activate
pip uninstall PyBeacon -y;
if [[ -f local_config.yml ]]; then
  LOCALCONFIG=true
  echo 'backing up local_config'
  cp local_config.yml /tmp/
fi

git clean -df
git reset --hard
if [[ $(git branch |grep -c foo) -lt 1 ]]; then
  git branch foo
else
  git branch -D foo && git branch foo
fi

if [[ `grep -q 'hcidump' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcidump commands still running. killing them."
    sudo killall hcidump
fi
if [[ `grep -q 'hcitool' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcitool commands still running. killing them."
    sudo killall hcitool
fi
>/var/log/pybeacon.log
git checkout foo&& git reset --hard&& git branch -D master
git fetch; git checkout master&&virtualenv --python=python3 ../PyBeacon&&. bin/activate&& pip install -r requirements.txt && pip install .
if [[ $LOCALCONFIG == true ]]; then
    echo "restoring local config"
    cp /tmp/local_config.yml .
fi
echo 'sleeping for 2 seconds to give you time to interrupt me before I start PyBeacon'
sleep 1
echo 'just kidding. too slow charlie.'
PyBeacon -s
