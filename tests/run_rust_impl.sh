#!/bin/bash

cargo build --release

time cargo run --release -- --testnet-dir tests/testnet_dir_mainnet_10k/ --mnemonics tests/testnet_dir_mainnet_10k/mnemonics.yml

# On 8 core Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
# 208 sec / 100_000 keys all with withdrawal credentials
# ~ 1.68 ms / validator
