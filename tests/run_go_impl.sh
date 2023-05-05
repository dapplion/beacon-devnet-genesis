#!/bin/bash

DOCKER_IMAGE=ethpandaops/ethereum-genesis-generator:1.0.16

docker pull $DOCKER_IMAGE

time docker run --rm --entrypoint=eth2-testnet-genesis \
  -v $PWD/tests/testnet_dir_mainnet_10k:/data \
  $DOCKER_IMAGE phase0 \
  --eth1-block "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --timestamp "1630000000" \
  --config /data/config.yaml \
  --mnemonics /data/mnemonics.yml \
  --tranches-dir /tmp/tranches \
  --state-output /data/genesis.ssz

# On 8 core Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
# 208 sec / 100_000 keys all with withdrawal credentials
# ~ 2.08 ms / validator
