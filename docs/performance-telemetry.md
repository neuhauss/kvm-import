# API performance telemetry

The API logs failed requests and requests that exceed a configurable latency
threshold. This helps identify slow SSH/libvirt operations from their API route
without logging request bodies, query strings, host addresses, credentials, or
terminal commands.

The default threshold is 1000 ms. Set `rancher.slowRequestThresholdMs` in the
Helm values (or `KVM_SLOW_REQUEST_MS` on the API deployment) to change it. Set
it to `0` to log every request. Failed requests with an HTTP 5xx response are
logged regardless of the threshold.

Each event includes the HTTP method, FastAPI route template, response status
when available, and elapsed milliseconds. For example:

```text
api_request_slow method=GET route=/kvm-api/hosts/{host_id}/cloud-native status=200 elapsed_ms=1243.7
```

Use the API container's standard logs to inspect these events. Routes with
repeated high latency are candidates for targeted SSH/libvirt profiling before
adding caching or concurrency.
