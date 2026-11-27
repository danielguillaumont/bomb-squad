# The sink: the only host on the detonation network.
FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64
COPY sink.py /opt/sink/sink.py
ENTRYPOINT ["python", "-u", "/opt/sink/sink.py"]
