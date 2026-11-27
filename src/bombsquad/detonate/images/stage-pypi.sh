#!/bin/sh
# Runs as detonate. pip builds and installs the artifact without its dependencies, then
# the import step imports it once, which also runs any .pth file it installed.
exec >/home/detonate/stage.log 2>&1
cd /home/detonate
python -m pip install --user --no-deps --no-index --no-build-isolation --no-cache-dir \
  --disable-pip-version-check "/detonate/in/$BS_ARTIFACT"
python /opt/detonate/import.py "$BS_PACKAGE"
