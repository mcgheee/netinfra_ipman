FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends git iproute2 iputils-ping libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ipman \
    && useradd --uid 10001 --gid ipman --create-home ipman \
    && setcap cap_net_raw=ep /usr/local/bin/python3.12
WORKDIR /app
COPY pyproject.toml README.md ./
COPY netinfra_ipman ./netinfra_ipman
RUN pip install --no-cache-dir .
ENV IPMAN_CONFIG=/etc/ipman/ipman-config.yml \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "netinfra_ipman.main:app", "--host", "127.0.0.1", "--port", "8000", "--workers", "1", "--no-proxy-headers", "--no-access-log"]
