#!/usr/bin/python
import asyncio
import base64
import json
import logging
import os

import aiohttp
from aiohttp import client, web
from multidict import MultiDict, MultiDictProxy

from mockbin.logfilter import *
from mockbin.promstats import *
from mockbin.tracing import *

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

instrument()
tracer = trace.get_tracer("mockbin")


@web.middleware
async def opentelemetry(request, handler):
    _ctx = get_tracecontext()

    tracer = trace.get_tracer("aiohttp.server")
    with tracer.start_as_current_span(
        "aiohttp.handler", kind=trace.SpanKind.SERVER
    ) as span:
        TRACINGCALLS_TOTAL.inc()
        return await handler(request)


app = web.Application(middlewares=[opentelemetry])
app["outlier_enabled"] = False


async def metrics(req):
    return web.Response(
        status=200,
        headers={
            "Content-Type": "application/openmetrics-text",
            "MimeType": "application/openmetrics-text",
        },
        body=generate_metrics(),
    )


async def health(req):
    return web.Response(status=200, body="OK")


@measure
async def handler(req):
    status = 200
    headers = req.headers.copy()
    try:
        _ctx = get_tracecontext(headers=dict(headers))
        with tracer.start_as_current_span(
            "downstream request",
            attributes=dict(headers),
        ) as span:
            _sctx = span.get_span_context()
            TRACINGCALLS_TOTAL.inc()
            traceparent = f"00-{hex(_sctx.trace_id)[2:]}-{hex(_sctx.span_id)[2:]}-0{hex(_sctx.trace_flags)[2:]}"
            span.set_status(StatusCode.OK)
            headers = TraceContextTextMapPropagator().inject(dict(headers), _ctx)
            if headers == None:
                headers = req.headers.copy()
                _ctx = span.get_span_context()
                headers["traceparent"] = (
                    f"00-{hex(_ctx.trace_id)[2:]}-{hex(_ctx.span_id)[2:]}-0{hex(_ctx.trace_flags)[2:]}"
                )
            if app["outlier_enabled"]:
                logger.info(f"failing for outlier detection", _ctx=_ctx)
                span.add_event(
                    "outlier-detection",
                    attributes={"failing": "outlier-detection-test"},
                )
                status = 503
            HTTP_RESPONSES_TOTAL.labels(
                req.method, req.path, status, get_source(headers), "-"
            ).inc()
            return web.Response(
                status=status,
                body=json.dumps({"headers": dict(headers), "env": dict(os.environ)}),
            )
    except Exception as perr:
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(
            status=503,
            body=str(perr),
        )


@measure
async def handler_logging(req):
    status = 200
    headers = req.headers.copy()
    _ctx = get_tracecontext(headers=dict(headers))
    try:
        with tracer.start_as_current_span(
            "downstream request",
            attributes=dict(headers),
        ) as span:
            _sctx = span.get_span_context()
            logger.info(f"first log in context", _ctx=_ctx)
            TRACINGCALLS_TOTAL.inc()
            traceparent = f"00-{hex(_sctx.trace_id)[2:]}-{hex(_sctx.span_id)[2:]}-0{hex(_sctx.trace_flags)[2:]}"
            logger.warning(f"compiled traceparent {traceparent} in context", _ctx=_ctx)
            span.set_status(StatusCode.OK)
            headers = TraceContextTextMapPropagator().inject(dict(headers), _ctx)
            if headers == None:
                logger.debug(f"injection traceparent into headers", _ctx=_ctx)
                headers = req.headers.copy()
                _ctx = span.get_span_context()
                headers["traceparent"] = (
                    f"00-{hex(_ctx.trace_id)[2:]}-{hex(_ctx.span_id)[2:]}-0{hex(_ctx.trace_flags)[2:]}"
                )
            logger.debug(f"hitting metrics increment", _ctx=_ctx)
            HTTP_RESPONSES_TOTAL.labels(
                req.method, req.path, status, get_source(headers), "-"
            ).inc()
            logger.error(f"returning {status} for request", _ctx=_ctx)
            return web.Response(
                status=status,
                body=json.dumps({"headers": dict(headers), "env": dict(os.environ)}),
            )
    except Exception as perr:
        logger.error(f"Exception {perr}", _ctx=_ctx)
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(
            status=503,
            body=str(perr),
        )


def adjust_headers(headers):
    reqheaders = headers.copy()
    for h in (
        "Transfer-Encoding",
        "Content-Length",
        "Content-Encoding",
        "Accept-Encoding",
        "Origin",
        "Referer",
        "Host",
        "Vary",
    ):
        try:
            del reqheaders[h]
        except Exception as e:
            pass
    return reqheaders


def flatten_struct(headers):
    newheaders = {}
    for h in headers:
        if isinstance(headers[h], dict):
            newheaders.update(dict(flatten_struct(headers[h])))
            continue
        newheaders[h] = headers[h]
    return newheaders


def get_source(headers):
    return headers.get("x-forwarded-for", "").split(",")[0]


@measure
async def handler_proxy(req):
    status = 200
    headers = req.headers.copy()
    _ctx = get_tracecontext(headers=dict(headers))
    try:
        _reqdata = await req.post()
        reqdata = _reqdata.copy()
        reqquery = req.query.copy()

        rbody = []
        try:
            proxyurls = reqdata.get("proxy").split(",")
        except:
            proxyurls = []
        for dreq in proxyurls:
            with tracer.start_as_current_span(
                "downstream request",
                attributes=(
                    dict(flatten_struct(headers))
                    | dict(flatten_struct(reqdata))
                    | dict(flatten_struct(reqquery))
                ),
            ) as span:
                _c = span.get_span_context()
                TRACINGCALLS_TOTAL.inc()
                traceparent = f"00-{hex(_c.trace_id)[2:]}-{hex(_c.span_id)[2:]}-0{hex(_c.trace_flags)[2:]}"

                headers["traceparent"] = traceparent
                reqparams = {
                    "method": reqdata.get("method", "GET"),
                    "url": str(dreq),
                    "allow_redirects": True,
                    "ssl": False,
                    "headers": dict(adjust_headers(headers)),
                }
                span.set_status(StatusCode.OK)
                status_code = 200
                if reqdata.get("chain", False) is not False:
                    reqparams["data"] = {"proxy": reqdata.get("chain")}
                with tracer.start_as_current_span(
                    "upstream request",
                    attributes=dict(flatten_struct(reqparams)),
                ) as uspan:
                    TRACINGCALLS_TOTAL.inc()
                    try:
                        logger.info(f"calling {reqparams['url']}", _ctx=_ctx)
                        async with client.request(**reqparams) as resp:
                            urbody = await resp.read()
                            rheaders = dict(resp.headers.copy())
                            uspan.add_event(
                                "upstream response",
                                attributes={
                                    "status": resp.status,
                                }
                                | dict(flatten_struct(rheaders)),
                            )
                            try:
                                dbody = urbody.decode("utf8")
                            except:
                                pass
                            rbody.append(
                                {
                                    "proxy": dreq,
                                    "headers": rheaders,
                                    "body": dbody,
                                }
                            )
                            uspan.set_status(StatusCode.OK)
                            status_code = resp.status
                    except Exception as upsterr:
                        logger.error(f"upstream response Error {upsterr}", _ctx=_ctx)
                        status_code = 503
                        uspan.record_exception(upsterr)
                        uspan.set_status(StatusCode.ERROR)

        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(
            status=status_code,
            headers={"Content-type": "application/json", "traceparent": traceparent},
            body=json.dumps(rbody),
        )

    except Exception as perr:
        logger.error(f"Exception {perr}", _ctx=_ctx)
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(
            status=503,
            body=str(perr),
        )


@measure
async def handler_exception(req):
    status = 200
    headers = req.headers.copy()
    try:
        _ctx = get_tracecontext(headers=dict(headers))
        with tracer.start_as_current_span(
            "downstream request",
            attributes=dict(headers),
        ) as span:
            _sctx = span.get_span_context()
            TRACINGCALLS_TOTAL.inc()
            traceparent = f"00-{hex(_sctx.trace_id)[2:]}-{hex(_sctx.span_id)[2:]}-0{hex(_sctx.trace_flags)[2:]}"
            try:
                1 / 0
            except ZeroDivisionError as error:
                span.record_exception(error)
                span.set_status(StatusCode.ERROR)
                try:
                    status = int(req.path.split("/")[-1])
                except:
                    status = 500
                headers = TraceContextTextMapPropagator().inject(dict(headers), _ctx)
                if headers == None:
                    headers = req.headers.copy()
                    _ctx = span.get_span_context()
                    headers["traceparent"] = (
                        f"00-{hex(_ctx.trace_id)[2:]}-{hex(_ctx.span_id)[2:]}-0{hex(_ctx.trace_flags)[2:]}"
                    )
                HTTP_RESPONSES_TOTAL.labels(
                    req.method, req.path, status, get_source(headers), "-"
                ).inc()
                return web.Response(
                    status=status,
                    body=json.dumps(
                        {"headers": dict(headers), "env": dict(os.environ)}
                    ),
                )
    except Exception as perr:
        logger.error(f"Exception {perr}", _ctx=_ctx)
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(
            status=503,
            body=str(perr),
        )


@measure
async def handler_alert_receiver(req):
    status = 200
    headers = req.headers.copy()
    _ctx = get_tracecontext(headers=dict(headers))
    try:
        with tracer.start_as_current_span(
            "downstream request",
            attributes=dict(headers),
        ) as span:
            try:
                data = await req.json()
            except:
                data = await req.read()
                logger.error(
                    f"didn't receive json from downstream only body {body}", _ctx=_ctx
                )
            TRACINGCALLS_TOTAL.inc()
            try:
                with tracer.start_as_current_span(
                    "alert-receiver",
                    attributes={
                        "status": data.get("status"),
                        "count": len(data.get("alerts", [])),
                        "origin": get_source(headers),
                    },
                ) as aspan:
                    logger.debug(f"data for trace {dict(data)}", _ctx=_ctx)
                    TRACINGCALLS_TOTAL.inc()
                    for alert in data.get("alerts", []):
                        aspan.add_event("alert", attributes=dict(flatten_struct(alert)))
                        if data.get("status") == "resolved":
                            aspan.set_status(StatusCode.OK)
                        else:
                            aspan.set_status(StatusCode.ERROR)
                    logger.info(
                        f"received {len(data.get('alerts',[]))} from {get_source(headers)}",
                        _ctx=_ctx,
                    )
                span.set_attribute("cluster", alert.get("region", "local"))
                span.set_status(StatusCode.OK)
            except Exception as alterr:
                logger.error(f"Exception handling alert to trace {alterr}", _ctx=_ctx)
                span.record_exception(alterr)
                span.set_status(StatusCode.ERROR)

            HTTP_RESPONSES_TOTAL.labels(
                req.method, req.path, 201, get_source(headers), "-"
            ).inc()
            return web.Response(
                status=201,
            )
    except Exception as perr:
        logger.error(f"Exception handling alert to trace {perr}", _ctx=_ctx)
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(status=503, body=str(perr))


@measure
async def handler_outlier(req):
    status = 200
    headers = req.headers.copy()
    _ctx = get_tracecontext(headers=dict(headers))
    try:
        with tracer.start_as_current_span(
            "downstream request",
            attributes=dict(headers) | {"method": req.method},
        ) as span:
            TRACINGCALLS_TOTAL.inc()
            if req.method == "PUT":
                app["outlier_enabled"] = True
                span.add_event("outlier enabled")
            elif req.method == "DELETE":
                app["outlier_enabled"] = False
                span.add_event("outlier disabled")
    except Exception as perr:
        logger.error(f"Exception handling alert to trace {perr}", _ctx=_ctx)
        HTTP_RESPONSES_TOTAL.labels(
            req.method, req.path, 503, get_source(headers), "-"
        ).inc()
        return web.Response(status=503, body=str(perr))
    HTTP_RESPONSES_TOTAL.labels(
        req.method, req.path, 201, get_source(headers), "-"
    ).inc()
    return web.Response(status=201)


async def app_factory():
    app.router.add_route("*", "/health", health)
    app.router.add_route("GET", "/metrics", metrics)
    app.router.add_route("*", "/exception/{tail:.*}", handler_exception)
    app.router.add_route("*", "/logging/{tail:.*}", handler_logging)
    app.router.add_route("*", "/proxy/{tail:.*}", handler_proxy)
    app.router.add_route("*", "/{tail:.*}", handler)
    app.router.add_route("PUT", "/outlier", handler_outlier)
    app.router.add_route("DELETE", "/outlier", handler_outlier)
    app.router.add_route("*", "/webhook/alert-receiver", handler_alert_receiver)
    app["outlier_enabled"] = False
    return app


if __name__ == "__main__":
    print(f"Running on {os.environ.get('CERBOSAPI', 'http://localhost:3593')}")
    web.run_app(app_factory(), port=int(os.environ.get("PORT", 3985)))
