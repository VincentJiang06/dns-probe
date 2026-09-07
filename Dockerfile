FROM python:3.14-slim AS builder
WORKDIR /build
COPY . .
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.14-slim
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels dns-probe && rm -rf /wheels
USER 10001:10001
ENTRYPOINT ["dnsprobe"]
