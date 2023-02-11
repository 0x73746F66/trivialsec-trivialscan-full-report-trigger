import logging
from datetime import datetime, time, timezone
from os import getenv


CACHE_DIR = getenv("CACHE_DIR", "/tmp")
APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-dashboard-compliance-graphs")
DASHBOARD_URL = "https://www.trivialsec.com"
logger = logging.getLogger()


def date_label(date: datetime) -> tuple[str, str, int]:
    label = "a moment ago"
    group = "week"
    now = datetime.now(timezone.utc)
    delta = now - date
    if delta.days >= 365:
        group = "year"
        label = (
            f"{round(delta.days / 365, 0)} years ago"
            if delta.days <= 730
            else "1 year ago"
        )
    elif delta.days >= 31:
        group = "month"
        label = "1 month ago"
        if delta.days <= 60:
            label = f"{round(delta.days/30, 0)} months ago"
    elif delta.days == 0:
        label = "today"
    elif delta.days == 1:
        label = "1 day ago"
    elif delta.days >= 2:
        label = f"{delta.days} days ago"
    timestamp = datetime.combine(
        now - delta, time(0, 0, 0), tzinfo=timezone.utc
    ).timestamp()
    return label, group, round(timestamp)
