FROM rust:1.75-alpine AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Final stage
FROM alpine:3.20

WORKDIR /root/

COPY --from=builder /app/target/release/r2-backend .

EXPOSE 4000

CMD ["./r2-backend"]