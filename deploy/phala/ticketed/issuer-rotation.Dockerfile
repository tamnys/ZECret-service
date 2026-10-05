FROM ghcr.io/tamnys/zecret-service-preview@sha256:349006e0f54a8677f3bf0bf448fd916ada32f7324ee5db0838b7b68ee25092ab
USER 0:0
COPY --chmod=0444 issuer-public.der /opt/zrpc/ticket/issuer-public.der
USER 10001:0
