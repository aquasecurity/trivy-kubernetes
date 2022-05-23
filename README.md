# trivy-kubernetes

[![GoDoc](https://godoc.org/github.com/aquasecurity/trivy-kubernetes?status.svg)](https://godoc.org/github.com/aquasecurity/trivy-kubernetes)
![Build](https://github.com/aquasecurity/trivy-kubernetes/workflows/Build/badge.svg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/aquasecurity/trivy-kubernetes/blob/main/LICENSE)

Trivy Kubernetes Library.

Supports trivy <-> kubernetes communication for resources scanning.

Trivy example:

```
$ trivy k8s --report=summary
```

![k8s Summary Report](./imgs/k8s-summary.png)


# Documentation
Please check `trivy` documentation, which provides detailed installation, configuration, and quick start guides, is available at https://aquasecurity.github.io/trivy/.
