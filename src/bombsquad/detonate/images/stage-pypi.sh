#!/bin/sh
# Runs as detonate. pip builds and installs the artifact without its dependencies, then
# the import step imports it once, which also runs any .pth file it installed. When an
# sdist does not build here (its build dependencies are missing), the release's wheel is
# installed instead, so the import step still runs.
exec >/home/detonate/stage.log 2>&1
cd /home/detonate
install() {
  python -m pip install --user --no-deps --no-index --no-build-isolation --no-cache-dir \
    --disable-pip-version-check "/detonate/in/$1"
}
if ! install "$BS_ARTIFACT" && [ -n "${BS_FALLBACK:-}" ]; then
  install "$BS_FALLBACK"
fi
python /opt/detonate/import.py "$BS_PACKAGE"
