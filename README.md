# trivy-kubernetes

[![GoDoc](https://godoc.org/github.com/aquasecurity/trivy-kubernetes?status.svg)](https://godoc.org/github.com/aquasecurity/trivy-kubernetes)
![Build](https://github.com/aquasecurity/trivy-kubernetes/workflows/Build/badge.svg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/aquasecurity/trivy-kubernetes/blob/main/LICENSE)

Trivy Kubernetes Library.

Supports trivy <-> kubernetes communication for resources scanning.

# Description

This Lib purpose is to extend trivy capabilities with kubernetes context:

- Listing resources
- Run k8s jobs
- Listing [KBOM](https://blog.aquasec.com/introducing-kbom-kubernetes-bill-of-materials?_hsmi=264466512&_hsenc=p2ANqtz-9DJtsKBz4A4LToG20mmlCUYTZZa1frulphJ_HPS0FGtMvQ5E0UdSCMyvPX2ScYKr1QZ5tGeo4W3FN91xKZ2mcOa0pm6w)

# Documentation

Please check `trivy` documentation, which provides detailed installation, configuration, and quick start guides, available at [Trivy Kubernetes](https://aquasecurity.github.io/trivy/latest/docs/kubernetes/cli/scanning/)
