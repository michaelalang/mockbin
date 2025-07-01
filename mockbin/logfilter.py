import logging
import os
import socket
from collections import defaultdict
from functools import wraps

import rfc5424logging
from rfc5424logging import Rfc5424SysLogHandler

from .tracing import *

from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

logger_provider = LoggerProvider(
    resource=Resource.create(
        {
            "service.name": "mockbin",
            "service.instance.id": "mockin-aio-otel-log",
        }
    ),
)
set_logger_provider(logger_provider)

exporter = OTLPLogExporter(insecure=True)
logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)

# Set the root logger level to NOTSET to ensure all messages are captured
logging.getLogger().setLevel(logging.NOTSET)


LF_BASE, LF_WEB, LF_POLICY, LF_MODEL, LF_RESPONSES = range(5)

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
)

levels = defaultdict(bool)

syslog = Rfc5424SysLogHandler(
    address=("127.0.0.1", 50514),
    socktype=socket.SOCK_DGRAM,
    facility=rfc5424logging.LOG_DAEMON,
    hostname=socket.gethostname(),
    appname="prompolicy",
    procid=os.getpid(),
)

syslog.setLevel(logging.DEBUG)
tracer = trace.get_tracer("proxy")

try:
    for n in range(int(os.environ.get("DEBUG", 0))):
        levels[n] = True
except:
    pass


class FilteredLogger(object):
    def __init__(self, name, baselevel=logging.INFO, levels=levels, stream=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(baselevel)
        self.levels = levels
        self.logger.addHandler(syslog)
        self.logger.addHandler(handler)
        # initialize default level
        self.levels[0] = True

    def enhance(self, message: str, _ctx=None) -> str:
        try:
            traceparent = f"00-{hex(_ctx.trace_id)[2:]}-{hex(_ctx.span_id)[2:]}-01"
        except Exception as perr:
            try:
                if isinstance(_ctx, Context):
                    cspan = _ctx.get(list(_ctx.keys())[0]).get_span_context()
                    traceparent = (
                        f"00-{hex(cspan.trace_id)[2:]}-{hex(cspan.span_id)[2:]}-01"
                    )
            except Exception as perr:
                print(f"enhance Exception {perr} {type(_ctx)}")
                traceparent = ""
        message += f"#{traceparent}"
        return message

    def info(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.info(self.enhance(message, _ctx))

    def debug(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.debug(self.enhance(message, _ctx))

    def warning(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.warning(self.enhance(message, _ctx))

    def error(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.error(self.enhance(message, _ctx))
