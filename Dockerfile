FROM rust:1.82-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --bin qimem-api --features stateful && strip target/release/qimem-api

FROM debian:bookworm-slim
RUN useradd -m -u 10001 qimem
WORKDIR /app
COPY --from=builder /app/target/release/qimem-api /usr/local/bin/qimem-api
COPY migrations ./migrations
USER qimem
EXPOSE 8080
CMD ["qimem-api"]
