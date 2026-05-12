"""`python -m clinical_redteam.web` — runs the status app locally for dev.

Production uses gunicorn (see .deploy/Dockerfile). This entry point is
for local development against a checkout of evals/ artifacts.
"""

from clinical_redteam.web.status_app import main

if __name__ == "__main__":
    main()
