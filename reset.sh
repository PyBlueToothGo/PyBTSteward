#!/bin/bash
pip uninstall PyBeacon -y;
git clean -df
git reset --hard
if [[ $(git branch |grep -c foo) -lt 1 ]]; then
  git branch foo
fi
git checkout foo&& git reset --hard&& git branch -D master
git pull; git checkout master&&virtualenv --python=python3 ../PyBeacon&& pip install -r requirements.txt && pip install .&& PyBeacon -s
