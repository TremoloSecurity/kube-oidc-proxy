# Copyright Jetstack Ltd. See LICENSE for details.
FROM ubuntu:24.04
LABEL description="OIDC reverse proxy authenticator based on Kubernetes"

ARG TARGETARCH

RUN apt-get update;apt-get -y install ca-certificates;apt-get -y upgrade;apt-get clean;rm -rf /var/lib/apt/lists/*

COPY bin/${TARGETARCH}/kube-oidc-proxy /usr/bin/

CMD ["/usr/bin/kube-oidc-proxy"]
