# beacon-devnet-genesis

Generate beacon chain devnet genesis states from mnemonics

```
Generate beacon chain devnet genesis states from mnemonics

Usage: beacon-devnet-genesis [OPTIONS] --testnet-dir <TESTNET_DIR> --mnemonics <MNEMONICS>

Options:
      --testnet-dir <TESTNET_DIR>  Path to directory containing eth2_testnet specs
      --output <OUTPUT>            Output dir for genesis.ssz and tranches dir
      --eth1-block <ETH1_BLOCK>    Block hash of the execution genesis, or block hash of deposit contract deploy tx
      --mnemonics <MNEMONICS>      YAML file listing the mnemonic of genesis keys, in format
                                   \`\`\`yaml
                                   - mnemonic: "reward base tuna ..."  # a 24 word BIP 39 mnemonic
                                     count: 100  # amount of validators
                                   \`\`\`
  -h, --help                       Print help
  -V, --version                    Print version
``` 

If some fork happens at genesis (`ALTAIR_FORK_EPOCH = 0`) it will upgrade the state to the latest fork with epoch 0.

You can set withdrawal credentials for a set of validators in the mnemonics file:

```yaml
- mnemonic: "reward base tuna ..."  # a 24 word BIP 39 mnemonic
  count: 100  # amount of validators
- mnemonic: "hint dizzy fog ..."
  count: 9000
  withdrawal_execution_address: 0xabababababababababababababababababababab
  # ... more
```

## From dockerhub

```
docker run dapplion/beacon-devnet-genesis --help
```

## bin usage

```
cargo install beacon-devnet-genesis
```
```
beacon-devnet-genesis --help
```

## Example

```
cargo run -- --testnet-dir tests/testnet_dir_minimal/ --mnemonics tests/mnemonics.yml
```
