FROM alpine:latest@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d as ca-certificates
RUN apk add -U --no-cache ca-certificates

FROM scratch
ARG RUST_TARGET_DIR 

# Move the ca-certs across (required for tls to work)
COPY --from=ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY ${RUST_TARGET_DIR}/argocd-appset-checked-pr-generator /

CMD [ "/argocd-appset-checked-pr-generator" ]

