#!/bin/bash
source bin/activate
LOG=reset.log
>${LOG}
pip uninstall PyBTSteward -y >${LOG} $2>&1;
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
>/var/log/pybtsteward.log
git checkout foo >>${LOG} $2>&1 && git reset --hard >>${LOG} $2>&1 &&
git branch -D master
git fetch ; git checkout master
echo 'Creating virtualenv'
virtualenv --python=python3 ../PyBTSteward >>${LOG} $2>&1 &&
echo 'Settin up PyBTSteward'
. bin/activate >>${LOG} $2>&1 && pip install -r requirements.txt >>${LOG} $2>&1 &&
echo 'Pip'
pip install . >>${LOG} $2>&1
if [[ $LOCALCONFIG == true ]]; then
    echo "restoring local config"
    cp /tmp/local_config.yml .
fi
echo -n 'Sleeping a few seconds to give you time to interrupt me before I start PyBTSteward'
i=5;
while [[ $i > 0 ]]; do
    echo -n '.';sleep 1; let i=($i-1)
done
echo ' Last Chance.'
sleep 2
PyBTSteward -s
