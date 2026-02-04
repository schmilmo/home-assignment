FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

WORKDIR /root/

COPY --from=builder /app/target/release/r2_backend .

EXPOSE 4000

CMD ["./r2_backend"]