# The poaw reference node. Build from the repository root:  docker build -f node/Dockerfile .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir "uv>=0.5"
WORKDIR /src
COPY core-python ./core-python
COPY node ./node
RUN uv pip install --system --no-cache ./core-python "./node[anchor]"
RUN useradd --create-home --uid 10001 poaw && mkdir -p /keys && chown poaw /keys
USER poaw
COPY --chown=poaw node/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["sh", "/usr/local/bin/docker-entrypoint.sh"]
