FROM python:3.12-slim

LABEL maintainer="Team Beta"
LABEL description="Modular reconnaissance CLI - ITSOLERA Offensive Security Internship Task"

# Install nmap so --use-nmap works out of the box (optional but nice to have)
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/reports

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
