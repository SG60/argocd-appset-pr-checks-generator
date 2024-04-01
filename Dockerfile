FROM alpine:latest@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b as ca-certificates
RUN apk add -U --no-cache ca-certificates

FROM scratch
ARG RUST_TARGET_DIR 

# Move the ca-certs across (required for tls to work)
COPY --from=ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY ${RUST_TARGET_DIR}/argocd-appset-checked-pr-generator /

CMD [ "/argocd-appset-checked-pr-generator" ]

