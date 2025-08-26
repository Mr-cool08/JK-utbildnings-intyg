import os

workers = 2
threads = 2
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
accesslog = '-'
errorlog = '-'
timeout = 30
graceful_timeout = 30
