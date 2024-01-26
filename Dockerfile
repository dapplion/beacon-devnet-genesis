FROM rust:1.73.0-bullseye as builder
WORKDIR /app
RUN apt-get update && apt-get -y upgrade && apt-get install -y protobuf-compiler cmake libclang-dev
COPY . .
RUN cargo build --release

# Final layer to minimize size
FROM ubuntu:22.04
COPY --from=builder /app/target/release/beacon-devnet-genesis /beacon-devnet-genesis
ENTRYPOINT ["/beacon-devnet-genesis"]
