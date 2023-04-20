FROM rust:1.68.0 as builder
WORKDIR /app
RUN apt-get update && apt-get install -y protobuf-compiler
COPY . .
RUN cargo build --release

# Final layer to minimize size
FROM gcr.io/distroless/cc-debian11
COPY --from=builder /app/target/release/beacon-devnet-genesis /beacon-devnet-genesis
ENTRYPOINT ["/beacon-devnet-genesis"]
