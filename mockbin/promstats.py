import os
from functools import wraps
from time import time

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    multiprocess,
)
from prometheus_client.openmetrics.exposition import generate_latest

from .tracing import *

# registry = CollectorRegistry()
# multiprocess.MultiProcessCollector(registry)


tracer = trace.get_tracer("proxy")

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total requests recieved from downstream",
    ["method", "path", "downstream", "upstream"],
)
HTTP_RESPONSES_TOTAL = Counter(
    "http_responses_total",
    "Total responses send to downstream",
    ["method", "path", "code", "downstream", "upstream"],
)
HTTP_REQUESTS_LATENCY = Histogram(
    "requests_latency_seconds",
    "Requests latency in seconds to downsteam",
    ["method", "path", "downstream", "upstream"],
)

TRACINGCALLS_TOTAL = Counter(
    "tracingcalls_total",
    "Total tracing calls generated",
)


def generate_metrics():
    return generate_latest(REGISTRY)


def get_xforwarded_for(req):
    # "X-Forwarded-For":
    headers = req.headers.copy()
    try:
        return headers.get("x-forwarded-for", False).split(",")[0]
    except:
        return req.remote


def measure(func):
    @wraps(func)
    def measure(req):
        with tracer.start_as_current_span(
            "measure", kind=trace.SpanKind.SERVER
        ) as span:
            btime = time()
            rsp = func(req)
            etime = time()
            _ctx = span.get_span_context()
            traceparent = hex(_ctx.trace_id)[2:]
            uri = os.environ.get("PROMAPI", "http://127.0.0.1:8080")
            HTTP_REQUESTS_LATENCY.labels(
                req.method,
                req.path,
                "",
                uri,
            ).observe(btime - etime, exemplar={"trace_id": traceparent})
            HTTP_REQUESTS_LATENCY.labels(
                req.method,
                req.path,
                get_xforwarded_for(req),
                uri,
            ).observe(btime - etime, exemplar={"trace_id": traceparent})
            HTTP_REQUESTS_TOTAL.labels(
                req.method,
                req.path,
                req.remote,
                uri,
            ).inc(exemplar={"trace_id": traceparent})
            return rsp

    return measure
