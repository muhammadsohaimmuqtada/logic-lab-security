workers = 2
bind = "127.0.0.1:8000"

pidfile = "/run/logic-lab/gunicorn.pid"
worker_tmp_dir = "/run/logic-lab"

accesslog = "-"
errorlog = "-"
