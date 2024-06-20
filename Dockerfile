FROM alpine:latest@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0 as ca-certificates
RUN apk add -U --no-cache ca-certificates

FROM scratch
ARG RUST_TARGET_DIR 

# Move the ca-certs across (required for tls to work)
COPY --from=ca-certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY ${RUST_TARGET_DIR}/argocd-appset-checked-pr-generator /

CMD [ "/argocd-appset-checked-pr-generator" ]

