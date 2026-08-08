import os

workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
bind = os.environ.get("GUNICORN_BIND", "127.0.0.1:8000")
accesslog = "-"
errorlog = "-"
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "30"))
