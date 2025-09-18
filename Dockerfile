FROM rust:1.81.0-bullseye AS builder
WORKDIR /app
RUN apt-get update && apt-get -y upgrade && apt-get install -y protobuf-compiler cmake libclang-dev
COPY . .
RUN cargo build --release

# Final layer to minimize size
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/beacon-devnet-genesis /beacon-devnet-genesis
ENTRYPOINT ["/beacon-devnet-genesis"]
