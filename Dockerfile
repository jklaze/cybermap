FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Both services (DataServer and AttackMapServer) are baked in;
# the compose command selects which one to run.
COPY DataServer/ ./DataServer/
COPY AttackMapServer/ ./AttackMapServer/
