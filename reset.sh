#!/bin/bash
source bin/activate
pip uninstall PyBeacon -y;
git clean -df
git reset --hard
if [[ $(git branch |grep -c foo) -lt 1 ]]; then
  git branch foo
fi
if [[ `grep -q 'hcidump' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcidump commands still running. Might want to kill them."
fi
if [[ `grep -q 'hcitool' /proc/[[:digit:]]*/cmdline; echo $?` > 0 ]]; then
    echo "Hcitool commands still running. Might want to kill them."
fi
>/var/log/pybeacon.log
git checkout foo&& git reset --hard&& git branch -D master
git fetch; git checkout master&&virtualenv --python=python3 ../PyBeacon&&. bin/activate&& pip install -r requirements.txt && pip install .&& PyBeacon -s
