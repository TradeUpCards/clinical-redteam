# Clinical Red Team Platform — droplet deployment image.
#
# One image, two entry points:
#   - daemon: `python -m clinical_redteam.run --continuous ...`
#   - status: `gunicorn --bind 0.0.0.0:8080 clinical_redteam.web.status_app:create_app()`
#
# Sibling services in `.deploy/docker-compose.redteam.yml` pick the
# entry point via `command:`. The image itself stays generic.
#
# Build context = repo root. The compose file sets context: ".." so
# this Dockerfile can `COPY src/ ./src/` etc.
#
# Threat-model notes (THREAT_MODEL.md §H attacker self-defense):
#   - Runs as non-root user `redteam` (uid 1000). No host-FS writes
#     outside the mounted /app/evals volume.
#   - No build-time secrets. .env mounted at runtime, never baked in.
#   - Pinned Python 3.12-slim base (matches the version we test against).
#   - Layer caching: copy pyproject + lock first, install, THEN copy
#     code. Source-only edits don't re-trigger the dep install.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps:
#   curl    — used in HEALTHCHECK
#   git     — pip occasionally needs it for direct-from-git deps even
#             when our pyproject doesn't (defensive; tiny size cost)
#   tini    — proper PID-1 reaper so SIGTERM propagates to gunicorn /
#             daemon cleanly on `docker compose stop`
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for the runtime. /app owned by this user so pip-install
# of the editable package can write the .egg-info.
RUN useradd --create-home --shell /bin/bash --uid 1000 redteam
WORKDIR /app

# --- Dependency layer (rebuilds only when requirements*.txt change) -----
# Install deps directly from requirements files — NOT from pyproject.toml's
# editable install. Reason: pyproject has `version = { attr = "clinical_
# redteam.__version__" }` which needs src/ on disk to resolve. The dep
# layer doesn't have src/ yet (it's the next layer), so an editable
# install here fails with ModuleNotFoundError: clinical_redteam. By
# installing only requirements.txt + requirements-dev.txt here, we get
# the heavy dep resolution cached without touching the dynamic-version
# machinery.
COPY requirements.txt requirements-dev.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -r requirements-dev.txt \
    && pip install "gunicorn>=21.2.0"

# --- Source layer (rebuilds on every src/ edit) -----------------------
COPY pyproject.toml ./
COPY src/ ./src/
COPY evals/ ./evals/
COPY ARCHITECTURE.md THREAT_MODEL.md README.md SETUP.md USERS.md RESPONSIBLE_USE.md LICENSE ./

# Editable install — registers the `clinical-redteam` console script
# + egg-info pointing at /app/src. Deps are already cached above so
# this is fast (pip sees requirements satisfied, only adds the egg).
RUN pip install -e . --no-deps

# Writable evals dir under the non-root user. Compose will bind-mount
# over this at runtime, but the ownership has to exist BEFORE the mount
# so that the daemon can write `evals/results/<run-id>/` from inside.
RUN chown -R redteam:redteam /app
USER redteam

# Daemon's default cost ceiling — overridable via env. Conservative so
# an unsupervised container can't burn beyond this without explicit
# action. See ARCH §8 cost guardrails.
ENV MAX_SESSION_COST_USD=5.00 \
    EVALS_DIR=/app/evals \
    RESULTS_DIR=/app/evals/results \
    LOG_LEVEL=INFO

# Tini is PID 1; the compose `command:` overrides what tini exec's.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default to status app (port 8080). Compose overrides for the daemon
# service to run `python -m clinical_redteam.run --continuous ...`.
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", \
     "--workers", "2", "--threads", "4", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "clinical_redteam.web.status_app:create_app()"]

# Healthcheck for both modes:
#   - status: hits its own /health on 8080
#   - daemon: 8080 returns refused (no listener); HEALTHCHECK will fail
#     and compose's `restart: always` keeps the container alive anyway
# Compose overrides healthcheck for the daemon service (checks process
# liveness via `pgrep -f clinical_redteam.run` instead).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1
