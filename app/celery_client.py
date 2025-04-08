from celery import Celery
import os

REDIS_BROKER_URL = os.getenv("REDIS_BROKER_URL", "redis://10.128.0.4:6379/0")  # IP interna de Worker donde Redis corre

celery = Celery('tasks', broker=REDIS_BROKER_URL)