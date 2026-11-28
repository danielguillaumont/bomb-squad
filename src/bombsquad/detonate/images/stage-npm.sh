#!/bin/sh
# Runs as detonate. The package is unpacked in node_modules; rebuild runs its preinstall,
# install and postinstall scripts (and node-gyp for binding.gyp) as installing would.
# Its dependencies, fetched before the sandbox started, are in node_modules beside it;
# their own install scripts are not run.
exec >/home/detonate/stage.log 2>&1
cd /home/detonate/project
exec npm rebuild --foreground-scripts --offline "$BS_PACKAGE"
