FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

# install Python deps later when you add them (for now it's fine)
# RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "-m", "overwatch_core.cli"]
