# Optional Docker Registry example

`registry.yaml` is an optional single-instance Distribution Registry example. It is not required to build or install Rancher KVM Manager; the project publishes the API image through GitHub Actions to GHCR, with optional Docker Hub publishing.

Before using this example, create the `registry-auth` and `registry-tls` Secrets, configure persistent storage for a StorageClass available in your cluster, and expose the service through an address reachable by Docker clients and Kubernetes nodes.

Do not commit passwords, access tokens, or private TLS keys. Install the registry CA on clients and nodes that pull images. This example does not replicate storage or provide high availability, so it is not intended as a production registry without further hardening.
