# The PyPI detonation image. Build backends are preinstalled because the network reaches
# only the sink, so pip builds without isolation and without an index.
FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir --disable-pip-version-check setuptools==84.2.1 wheel==0.48.0 \
      hatchling==1.33.0 flit-core==4.2.0 poetry-core==2.5.0 pdm-backend==2.5.0 \
      setuptools-scm==10.3.4 \
 && useradd --create-home --uid 1001 --shell /bin/sh detonate \
 && mkdir -p /detonate/in
COPY entry.sh /opt/detonate/entry.sh
COPY stage-pypi.sh /opt/detonate/stage.sh
COPY import.py /opt/detonate/import.py
RUN chmod 0555 /opt/detonate/entry.sh /opt/detonate/stage.sh \
 && chmod 0444 /opt/detonate/import.py
ENTRYPOINT ["/opt/detonate/entry.sh"]
