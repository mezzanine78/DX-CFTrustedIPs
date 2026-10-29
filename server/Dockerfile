# DX Cloudflare trusted-IP updater - report endpoint + hourly list sync. Stdlib only, no pip deps.
# :latest per Ryan's convention; pin (e.g. python:3.13-slim) if you want reproducible builds.
FROM python:latest
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv
COPY cfip ./cfip
RUN useradd --system --uid 10001 --no-create-home cfip \
    && mkdir -p /data && chown cfip /data && chmod 700 /data
USER cfip
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"
ENTRYPOINT ["python", "-m", "cfip"]
CMD ["serve"]
