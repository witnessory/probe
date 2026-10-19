# The Witnessory probe in a container.
#
#   docker build -t witnessory-probe .
#   docker run -d --name witnessory-probe --restart unless-stopped --stop-timeout 120 -v witnessory-probe:/data witnessory-probe
#   docker exec witnessory-probe witnessory-probe me
#
# The volume keeps the probe's keys and results; without it a new probe is created at every start.
FROM python:3.12-slim
LABEL org.opencontainers.image.source=https://github.com/witnessory/probe \
      org.opencontainers.image.description="The Witnessory probe" \
      org.opencontainers.image.licenses=Apache-2.0
RUN useradd --system --create-home --home-dir /data --shell /usr/sbin/nologin probe
COPY pyproject.toml README.md LICENSE NOTICE /src/
COPY witnessory_probe /src/witnessory_probe
RUN pip install --no-cache-dir /src && rm -rf /src
USER probe
ENV WITNESSORY_PROBE_HOME=/data PYTHONIOENCODING=utf-8 PYTHONUNBUFFERED=1
VOLUME /data
ENTRYPOINT ["witnessory-probe"]
CMD ["start"]
