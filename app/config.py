import os


class Config:
    """Deliberately weak config — this is a vulnerable-by-design lab, not production code."""

    SECRET_KEY = "vulnlab-static-secret-key"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:////tmp/vulnlab.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # A02: password-reset tokens are derived from this "secret" launch date.
    # It's hardcoded and shipped in the public repo -> not actually secret. That's the vuln.
    LAUNCH_DATE = "2024-01-01"

    # A05: verbose/debug endpoints left reachable in what's supposed to be a "prod" build.
    DEBUG_ENDPOINTS_ENABLED = True
