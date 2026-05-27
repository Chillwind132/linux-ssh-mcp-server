FROM python:3.11-slim

RUN pip install --no-cache-dir \
    "fastmcp==3.2.3" \
    "paramiko==3.5.1"

COPY app.py /app/app.py
COPY agent  /app/agent

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /app/logs

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
