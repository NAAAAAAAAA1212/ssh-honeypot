FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    fonts-freefont-ttf && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -u 1000 -d /app honeypot && \
    mkdir -p /app/logs && \
    chown honeypot:honeypot /app/logs

USER honeypot

COPY --chown=honeypot:honeypot . .

ENV TERM=xterm-256color \
    PYTHONUNBUFFERED=1

EXPOSE ${SSH_PORT:-2222} ${HTTP_PORT:-8080}

CMD ["python", "ssh_honeypot.py"]

LABEL org.opencontainers.image.source=https://github.com/naaaaaaaaa1212/ssh-honeypot