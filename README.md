# Mockbin python based Simple Service

inspired by httpbin, and lacking the possibility to include tracing,metrics and logging in particular inside a ServiceMesh deployment I wrote up a small aiohttp based daemon providing these functionality.

## deployment

### build the image 

* build and push the image which is based upon Fedora 42 and python3.13 to your registry by executing following commands

```
podman build -f Dockerfile -t <my-registry>/<organization>/<repo>/<image>:<tag> 
podman push <my-registry>/<organization>/<repo>/<image>:<tag>
```

### deploy in ServiceMesh

* ensure to create the namespace with the proper labels (and ServiceMeshMember CR's for < 3.x) for ServiceMesh integration by executing following commands

```
oc create namespace <ns>
oc label namespace <ns> istio-injection=enabled 
# or 
# oc label namespace <ns> istio.io/rev=<revision>
```

* update the `kustomization.yaml` file in the `deploy/` directory with the namespace and image settings

**NOTE** the mockbin image name should match the one you used for building and pushing.

```
# Example configuration 
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- cm.yml
- deploy.yml
- service.yml

namespace: testnamespace
images:
- name: localhost/mockbin
  newName: quay.io/organization/myrepo/mockbin
  newTag: v1.0.0
- name: localhost/opentelemetry-collector-contrib
  newName: quay.io/otel/opentelemetry-collector-contrib
  newTag: 0.121.0
```

* add your desired ServiceMesh configuration to access the application


## example use cases 

### simple header and env response 

the endpoint `/` takes all HTTP methods (GET,POST,PUT,..) as well as any path except explicitly defined ones.

```
curl https://mockbin-ns1.apps.example.com -s | jq -r 
```

    output
    {
      "headers": {
        "Host": "mockbin-ns1.apps.example.com",
        "User-Agent": "curl/7.76.1",
        "Accept": "*/*",
        "X-Forwarded-For": "192.168.192.14,10.133.0.13",
        "X-Forwarded-Proto": "https",
        "x-request-id": "bed7875b-778c-92b7-b7d2-fca1dcf22517",
        "x-envoy-external-address": "10.133.0.13",
        "x-envoy-attempt-count": "1",
        "x-forwarded-client-cert": "By=spiffe://cluster.local/ns/ns1/sa/default;Hash=a25ef5e098424ee119cc5e2946f18df7c6c6407d006cac108abbe3a0875274a2;Subject=\"\";URI=spiffe://cluster.local/ns/ns1/sa/default",
        "traceparent": "00-5d7f18193e1b1249a921375c6939a8f-bebb3ad92b4bcd73-01",
        "tracestate": ""
      },
    ...

### simple exception handling 

the endpoint `/exception/.+` returns the normal response and changes the HTTP status code to any integer in the path

* to return HTTP status `499` execute following command 
```
curl https://mockbin-ns1.apps.example.com/exception/499 -I
```

    output 

    HTTP/1.1 499 Unknown
    content-type: text/plain; charset=utf-8
    content-length: 3225
    date: Tue, 01 Jul 2025 06:13:58 GMT
    server: envoy
    x-envoy-upstream-service-time: 15

* to return HTTP status `501` execute following command
```
curl https://mockbin-ns1.apps.example.com/exception/501 -I
```

    output 

    HTTP/1.1 501 Not Implemented
    content-type: text/plain; charset=utf-8
    content-length: 3227
    date: Tue, 01 Jul 2025 06:14:32 GMT
    server: envoy
    x-envoy-upstream-service-time: 17

* to return HTTP status `502` execute following command
```
curl https://mockbin-ns1.apps.example.com/exception/502 -I
```

    output 

    HTTP/1.1 502 Bad Gateway
    content-type: text/plain; charset=utf-8
    content-length: 3227
    date: Tue, 01 Jul 2025 06:14:37 GMT
    server: envoy
    x-envoy-upstream-service-time: 63

### simple logging 

the endpoint `/logging/.+` creates more log lines for show-casing metric to trace to log correlation

```
curl https://mockbin-ns1.apps.example.com/logging/something
```

The logs are only visible in the OTEL collector or your signal Storage.

### outlier detection 

then endpoint `/outlier` takes `PUT` and `DELETE` methods for enabling/disabling outlier detection tests.
With `PUT` all sub sequent calls to the service will be return with HTTP status `503` which will take the endpoint out of the Service pool.
Using `DELETE` will re-enable normal operations to the service.

* call the service to ensure it is working properly by executing following command
```
curl https://mockbin-ns1.apps.example.com -sI 
```

    output

    HTTP/1.1 200 OK
    content-type: text/plain; charset=utf-8
    content-length: 3225
    date: Tue, 01 Jul 2025 06:19:07 GMT
    server: envoy
    x-envoy-upstream-service-time: 14

* enable outlier detection by executing following command
```
curl https://mockbin-ns1.apps.example.com/outlier -X PUT -I
```
    output 

    HTTP/1.1 201 Created
    content-length: 0
    date: Tue, 01 Jul 2025 06:19:27 GMT
    server: envoy
    x-envoy-upstream-service-time: 15

* verify the service returns HTTP status `503` by executing following command

```
curl https://mockbin-ns1.apps.example.com -sI 
```

    output 

    HTTP/1.1 503 Service Unavailable
    content-type: text/plain; charset=utf-8
    content-length: 3224
    date: Tue, 01 Jul 2025 06:19:35 GMT
    server: envoy
    x-envoy-upstream-service-time: 67

* disable outlier detection by executing following command

```
curl https://mockbin-ns1.apps.example.com/outlier -X DELETE -I
```

    output 
        
    HTTP/1.1 201 Created
    content-length: 0
    date: Tue, 01 Jul 2025 06:19:45 GMT
    server: envoy
    x-envoy-upstream-service-time: 11

* wait for the ejection period to re-enable the endpoint and verify by executing following command

```
curl https://mockbin-ns1.apps.example.com -sI 
```

    output 
    
    HTTP/1.1 200 OK
    content-type: text/plain; charset=utf-8
    content-length: 3226
    date: Tue, 01 Jul 2025 06:20:11 GMT
    server: envoy
    x-envoy-upstream-service-time: 16

### AlertManager webhook 

the endpoint `/webhook/alert-receiver` takes OpenShift AlertManager notifications and translates them into Traces and trace events.

* configure your OCP Alertmanager notifications like

```
# Example configuration

receivers:
  - name: Critical
    webhook_configs:
      - url: 'https://mockbin-ns1.apps.example.com/webhook/alert-receiver'
  - name: Default
    webhook_configs:
      - url: 'https://mockbin-ns1.apps.example.com/webhook/alert-receiver'
  - name: 'null'
  - name: Watchdog
```
