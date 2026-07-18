# Minimal image for running the Bug Bounty Toolkit test suite in CI / Docker.
FROM python:3.12-slim

WORKDIR /app

# Avoid interactive prompts during package installs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt || true

COPY . /app

# Default entrypoint runs the test suite; override for other uses.
CMD ["python", "-m", "pytest", "toolkit/tests/", "-q"]
