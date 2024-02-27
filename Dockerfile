FROM scratch
ARG RUST_TARGET_DIR 

COPY ${RUST_TARGET_DIR}/argocd-appset-checked-pr-generator /

CMD [ "/argocd-appset-checked-pr-generator" ]

