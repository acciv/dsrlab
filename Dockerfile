FROM rust:1.77-bookworm AS rust-build
WORKDIR /src
COPY . .
RUN cargo build --release --manifest-path Cargo.toml

FROM golang:1.22-bookworm AS go-build
WORKDIR /src
COPY . .
RUN cd go && CGO_ENABLED=0 go build -o bin/dstoken ./cmd/dstoken \
    && CGO_ENABLED=0 go build -o bin/dsmock ./cmd/dsmock

FROM python:3.12-slim
WORKDIR /work
COPY --from=rust-build /src/target/release/dscore /usr/local/bin/dscore
COPY --from=go-build /src/go/bin/dstoken /usr/local/bin/dstoken
COPY --from=go-build /src/go/bin/dsmock /usr/local/bin/dsmock
COPY python /opt/dsrlab/python
COPY configs /opt/dsrlab/configs
COPY examples /opt/dsrlab/examples
ENV PYTHONPATH=/opt/dsrlab/python
ENV TGSEC_CORE=/usr/local/bin/dscore
ENV TGSEC_DSTOKEN=/usr/local/bin/dstoken
ENV TGSEC_DSMOCK=/usr/local/bin/dsmock
CMD ["python3", "-m", "dsrlab", "help"]
