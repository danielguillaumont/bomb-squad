# The npm detonation image. Built from these files only; nothing is mounted at run time.
FROM node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1001 --shell /bin/sh detonate \
 && mkdir -p /detonate/in
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
COPY entry.sh /opt/detonate/entry.sh
COPY stage-npm.sh /opt/detonate/stage.sh
RUN chmod 0555 /opt/detonate/entry.sh /opt/detonate/stage.sh
ENTRYPOINT ["/opt/detonate/entry.sh"]
