#!/bin/sh
# Runs as detonate. pip builds and installs the artifact with the dependency wheels
# fetched before the sandbox started, or, if they do not satisfy it, without its
# dependencies. Then the import step imports it once, which also runs any .pth file it
# installed. When an sdist does not build here (its build dependencies are missing), the
# release's wheel is installed instead, so the import step still runs.
exec >/home/detonate/stage.log 2>&1
cd /home/detonate
pip_install() {
  python -m pip install --user --no-index --no-build-isolation --no-cache-dir \
    --disable-pip-version-check "$@"
}
install() {
  if [ -d /detonate/deps ] && pip_install --find-links /detonate/deps "/detonate/in/$1"; then
    return 0
  fi
  pip_install --no-deps "/detonate/in/$1"
}
if ! install "$BS_ARTIFACT" && [ -n "${BS_FALLBACK:-}" ]; then
  install "$BS_FALLBACK"
fi
python /opt/detonate/import.py "$BS_PACKAGE"
