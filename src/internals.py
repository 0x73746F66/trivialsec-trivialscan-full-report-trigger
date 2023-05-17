# pylint: disable=line-too-long
import contextlib
import json
import logging
import threading
from inspect import getframeinfo, stack
from time import sleep
from datetime import date, datetime
from os import getenv
from typing import Union
from uuid import UUID
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)

import boto3
import requests
from lumigo_tracer import (
    add_execution_tag,
    error as lumigo_error,
    info as lumigo_info,
    warn as lumigo_warn,
)
from pydantic import (
    HttpUrl,
    AnyHttpUrl,
    PositiveInt,
    PositiveFloat,
)


CACHE_DIR = getenv("CACHE_DIR", default="/tmp")
JITTER_SECONDS = int(getenv("JITTER_SECONDS", default="30"))
APP_ENV = getenv("APP_ENV", default="Dev")
APP_NAME = getenv("APP_NAME", default="trivialscan-full-report-trigger")
DEFAULT_LOG_LEVEL = "WARNING"
LOG_LEVEL = getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)
NAMESPACE = UUID("bc6e2cd5-1f59-487f-b05b-49946bd078b2")
APEX_DOMAIN = "trivialsec.com"
ORIGIN_HOST = f"dev.{APEX_DOMAIN}" if APP_ENV == "Dev" else f"www.{APEX_DOMAIN}"
DASHBOARD_URL = f"https://{ORIGIN_HOST}"
UNHANDLED_ERROR = "UnhandledError"

logger = logging.getLogger(__name__)
boto3.set_stream_logger("boto3", getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))  # type: ignore
logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))


def always_log(message: Union[str, Exception], is_issue: bool = True):
    caller = getframeinfo(stack()[1][0])
    alert_type = (
        message.__class__.__name__
        if hasattr(message, "__class__") and message is not str
        else UNHANDLED_ERROR
    )
    filename = (
        caller.filename.replace(getenv("LAMBDA_TASK_ROOT", ""), "")
        if getenv("AWS_EXECUTION_ENV") is not None and getenv("LAMBDA_TASK_ROOT")
        else caller.filename.split("/src/")[1]
    )
    if not is_issue:
        lumigo_info(
            f"{filename}:{caller.function}:{caller.lineno} - {message}",
            "Info",
        )
    if alert_type == UNHANDLED_ERROR:
        lumigo_warn(
            f"{filename}:{caller.function}:{caller.lineno} - {message}",
            alert_type,
            extra={
                "LOG_LEVEL": LOG_LEVEL,
                "NAMESPACE": NAMESPACE.hex,
            },
        )
    else:
        lumigo_error(
            f"{filename}:{caller.function}:{caller.lineno} - {message}", alert_type
        )


class InvalidTriggerEvent(Exception):
    """
    Deny Invoke attempt using invalid event
    """


class DelayRetryHandler(Exception):
    """
    Delay the retry handler and provide a useful message when retries are exceeded
    """
    def __init__(self, **kwargs):
        sleep(kwargs.get("delay", 3) or 3)
        Exception.__init__(self, kwargs.get("msg", "Max retries exceeded"))


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, date):
            return o.isoformat()
        if isinstance(o, datetime):
            return o.replace(microsecond=0).isoformat()
        if isinstance(o, int) and o > 10 ^ 38 - 1:
            return str(o)
        if isinstance(
            o,
            (
                PositiveInt,
                PositiveFloat,
            ),
        ):
            return int(o)
        if isinstance(
            o,
            (
                HttpUrl,
                AnyHttpUrl,
                IPv4Address,
                IPv6Address,
                IPv4Network,
                IPv6Network,
                UUID,
            ),
        ):
            return str(o)
        if hasattr(o, "dict"):
            return json.dumps(o.dict(), cls=JSONEncoder)

        return super().default(o)


def _request_task(url: str, body: dict, headers: dict):
    with contextlib.suppress(requests.exceptions.ConnectionError):
        requests.post(
            url,
            data=json.dumps(body, cls=JSONEncoder),
            headers=headers,
            timeout=(15, 30),
        )


def post_beacon(url: AnyHttpUrl, body: dict, headers: dict = None):  # type: ignore
    """
    A beacon is a fire and forget HTTP POST, the response is not
    needed so we do not even wait for one, so there is no
    response to discard because it was never received
    """
    if headers is None:
        headers = {"Content-Type": "application/json"}
    threading.Thread(target=_request_task, args=(url, body, headers)).start()


def trace_tag(data: dict[str, str]):
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data.items()
    ):
        raise ValueError
    for key, value in data.items():
        if 1 > len(key) > 50:
            logger.warning(
                f"Trace key must be less than 50 for: {key} See: https://docs.lumigo.io/docs/execution-tags#execution-tags-naming-limits-and-requirements"
            )
        if 1 > len(value) > 70:
            logger.warning(
                f"Trace value must be less than 70 for: {value} See: https://docs.lumigo.io/docs/execution-tags#execution-tags-naming-limits-and-requirements"
            )
    if getenv("AWS_EXECUTION_ENV") is None or APP_ENV != "Prod":
        return
    for key, value in data.items():
        add_execution_tag(key[:50], value=value[:70])
