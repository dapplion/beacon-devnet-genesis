use anyhow::{anyhow, Result};
use clap::Parser;
use eth2_network_config::Eth2NetworkConfig;
use eth2_serde_utils::hex;
use eth2_wallet::bip39::Seed;
use eth2_wallet::bip39::{Language, Mnemonic};
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType};
use genesis::{bls_withdrawal_credentials, DEFAULT_ETH1_BLOCK_HASH};
use rayon::prelude::*;
use serde::Deserialize;
use ssz::{Decode, Encode};
use state_processing::common::DepositDataTree;
use state_processing::upgrade::{upgrade_to_altair, upgrade_to_bellatrix, upgrade_to_capella};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_hash::TreeHash;
use types::{
    BeaconState, Epoch, Eth1Data, EthSpec, EthSpecId, ExecutionBlockHash,
    ExecutionPayloadHeaderCapella, GnosisEthSpec, Hash256, MainnetEthSpec, MinimalEthSpec,
    PublicKeyBytes, SecretKey, Transactions, Uint256, Validator, Withdrawal, Withdrawals,
    DEPOSIT_TREE_DEPTH,
};
use types::{ChainSpec, Keypair};

#[derive(Debug, Deserialize)]
struct MnemonicEntry {
    mnemonic: String,
    count: u32,
    withdrawal_execution_address: Option<String>,
}

const GENESIS_EPOCH: Epoch = Epoch::new(0);

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to directory containing eth2_testnet specs.
    #[arg(long)]
    testnet_dir: String,

    /// Output dir for genesis.ssz and tranches dir
    #[arg(long)]
    output: Option<String>,

    /// Block hash of the execution genesis, or block hash of deposit contract deploy tx
    #[arg(long)]
    eth1_block: Option<String>,

    /// YAML file listing the mnemonic of genesis keys, in format
    /// ```yaml
    /// - mnemonic: "reward base tuna ..."  # a 24 word BIP 39 mnemonic
    ///   count: 100  # amount of validators
    /// ```
    #[arg(long)]
    mnemonics: String,
}

pub fn run(cli: Cli) -> Result<()> {
    let eth2_network_config = Eth2NetworkConfig::load(cli.testnet_dir.clone().into())
        .map_err(|e| anyhow!("Unable to load testnet_dir {}: {:?}", &cli.testnet_dir, e))?;
    match eth2_network_config
        .eth_spec_id()
        .map_err(|e| anyhow!("Invalid spec_id: {:?}", e))?
    {
        EthSpecId::Mainnet => run_with_spec::<MainnetEthSpec>(eth2_network_config, &cli),
        EthSpecId::Gnosis => run_with_spec::<GnosisEthSpec>(eth2_network_config, &cli),
        EthSpecId::Minimal => run_with_spec::<MinimalEthSpec>(eth2_network_config, &cli),
    }?;
    Ok(())
}

fn run_with_spec<T: EthSpec>(eth2_network_config: Eth2NetworkConfig, cli: &Cli) -> Result<()> {
    let spec = &eth2_network_config
        .chain_spec::<T>()
        .map_err(|e| anyhow!("chain_spec error: {:?}", e))?;

    let genesis_time = spec.min_genesis_time + spec.genesis_delay;
    let eth1_block_arg = Eth1BlockCliArg::parse_from_cli(cli)?;
    let eth1_block_hash = eth1_block_arg.hash()?;
    let eth1_data = empty_eth1_data(eth1_block_hash);
    let mut state = BeaconState::<T>::new(genesis_time, eth1_data, spec);

    if let Ok(state) = state.as_capella_mut() {
        let eth1_block = match eth1_block_arg {
            Eth1BlockCliArg::NotSet => {
                return Err(anyhow!("Must set eth1_block for capella genesis state"))
            }
            Eth1BlockCliArg::Hash(_) => {
                return Err(anyhow!(
                "Must set eth1_block to a block JSON not just the hash for capella genesis state"
            ))
            }
            Eth1BlockCliArg::Block(block) => block,
        };

        state.latest_execution_payload_header =
            exec_json_block_to_execution_payload_header(eth1_block)?;
    };

    // Seed RANDAO with Eth1 entropy
    state.fill_randao_mixes_with(eth1_block_hash);

    // Track tranches for latter auditing
    let mut tranches = String::from("validator_index,pubkey");

    let mnemonic_args = parse_mnemonics_arg(cli)?;
    let seeds = mnemonic_args
        .iter()
        .map(|mnemonic_arg| seed_from_mnemonic(&mnemonic_arg.mnemonic))
        .collect::<Result<Vec<Seed>>>()?;

    let computed_validators = AtomicUsize::new(0);

    let validators = mnemonic_args
        .iter()
        .zip(seeds.iter())
        .flat_map(|(mnemonic_entry, seed)| {
            (0..mnemonic_entry.count).map(move |i| (mnemonic_entry, seed, i))
        })
        .collect::<Vec<_>>()
        .par_iter()
        .map(|(mnemonic_entry, seed, i)| {
            let pubkey: PublicKeyBytes = keypair_from_seed(seed, *i, KeyType::Voting)?.pk.into();
            let validator = Validator {
                pubkey,
                withdrawal_credentials: compute_withdrawal_credentials(
                    spec,
                    seed,
                    mnemonic_entry,
                    *i,
                )?,
                effective_balance: spec.max_effective_balance,
                slashed: false,
                activation_eligibility_epoch: GENESIS_EPOCH,
                activation_epoch: GENESIS_EPOCH,
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
            };

            let completed = computed_validators.fetch_add(1, Ordering::Relaxed);
            if completed % 1000 == 0 {
                eprintln!("computed validators {}", completed)
            }
            Ok(validator)
        })
        .collect::<Result<Vec<Validator>>>()?;

    for validator in validators {
        tranches.push_str(&format!(
            "\n{},{}",
            state.validators().len(),
            validator.pubkey.as_hex_string(),
        ));
        state.validators_mut().push(validator).unwrap();
        state
            .balances_mut()
            .push(spec.max_effective_balance)
            .unwrap();
    }

    let validators_count = state.validators().len();
    if validators_count < spec.min_genesis_active_validator_count as usize {
        return Err(anyhow!(
            "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT is less than total sum of mnemonics count {} < {}",
            validators_count,
            spec.min_genesis_active_validator_count
        ));
    }

    // Advance state to fork with highest epoch 0
    if spec.altair_fork_epoch == Some(GENESIS_EPOCH) {
        upgrade_to_altair(&mut state, spec).unwrap();
    }
    if spec.bellatrix_fork_epoch == Some(GENESIS_EPOCH) {
        upgrade_to_bellatrix(&mut state, spec).unwrap();
    }
    if spec.capella_fork_epoch == Some(GENESIS_EPOCH) {
        upgrade_to_capella(&mut state, spec).unwrap();
    }

    // Persist output files
    let output = cli.output.clone().unwrap_or(cli.testnet_dir.clone());
    fs::create_dir_all(&output)?;
    fs::write(Path::new(&output).join("genesis.ssz"), state.as_ssz_bytes())?;
    fs::write(Path::new(&output).join("tranches.csv"), tranches)?;

    Ok(())
}

fn parse_mnemonics_arg(cli: &Cli) -> Result<Vec<MnemonicEntry>> {
    // Parse mnemonics
    let yaml_str = if cli.mnemonics.ends_with(".yaml") || cli.mnemonics.ends_with(".yml") {
        // If mnemonics is a path to a file
        fs::read_to_string(&cli.mnemonics)?
    } else {
        // Otherwise, assume it's a serialized YAML string
        cli.mnemonics.clone()
    };
    Ok(serde_yaml::from_str(&yaml_str)?)
}

enum Eth1BlockCliArg {
    NotSet,
    Hash(Hash256),
    Block(ethers_core::types::Block<ethers_core::types::Transaction>),
}

impl Eth1BlockCliArg {
    fn parse_from_cli(cli: &Cli) -> Result<Eth1BlockCliArg> {
        let Some(eth1_block_str) = cli.eth1_block.as_ref() else {
            return Ok(Eth1BlockCliArg::NotSet);
        };

        match hex::decode(&eth1_block_str) {
            Ok(hash) => return Ok(Eth1BlockCliArg::Hash(Hash256::from_slice(&hash))),
            Err(_) => {}
        };

        let eth1_block_str = cli
            .eth1_block
            .as_ref()
            .ok_or_else(|| anyhow!("should set eth1_block for capella genesis states"))?;

        let maybe_path = Path::new(&eth1_block_str);
        let eth1_block_json = if maybe_path.is_file() {
            // If the path points to a file that exists, read the file
            fs::read_to_string(maybe_path)?
        } else {
            // Otherwise, treat the input as a JSON string
            eth1_block_str.to_string()
        };

        Ok(Eth1BlockCliArg::Block(serde_json::from_str(
            &eth1_block_json,
        )?))
    }

    fn hash(&self) -> Result<Hash256> {
        match self {
            Eth1BlockCliArg::NotSet => Ok(Hash256::from_slice(&DEFAULT_ETH1_BLOCK_HASH.to_vec())),
            Eth1BlockCliArg::Hash(hash) => Ok(*hash),
            Eth1BlockCliArg::Block(block) => block.hash.ok_or_else(|| anyhow!("no block.hash")),
        }
    }
}

fn empty_eth1_data(eth1_block_hash: Hash256) -> Eth1Data {
    let deposit_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);
    Eth1Data {
        deposit_root: deposit_tree.root(),
        deposit_count: 0,
        block_hash: eth1_block_hash,
    }
}

fn keypair_from_seed(seed: &Seed, index: u32, key_type: KeyType) -> Result<Keypair> {
    let (secret, _) = recover_validator_secret_from_mnemonic(seed.as_bytes(), index, key_type)
        .map_err(|e| anyhow!("Unable to recover validator keys: {:?}", e))?;
    let sk = SecretKey::deserialize(secret.as_bytes())
        .map_err(|e| anyhow!("Invalid secret key bytes: {:?}", e))?;
    let pk = sk.public_key();
    Ok(Keypair::from_components(pk, sk))
}

fn seed_from_mnemonic(mnemonic: &str) -> Result<Seed> {
    Ok(Seed::new(
        &Mnemonic::from_phrase(mnemonic, Language::English)?,
        "",
    ))
}

fn eth1_withdrawal_credentials(execution_address: &[u8], spec: &ChainSpec) -> Hash256 {
    let mut credentials = [0u8; 32];
    credentials[0] = spec.eth1_address_withdrawal_prefix_byte;
    credentials[12..].copy_from_slice(execution_address);
    Hash256::from_slice(&credentials)
}

fn compute_withdrawal_credentials(
    spec: &ChainSpec,
    seed: &Seed,
    entry: &MnemonicEntry,
    index: u32,
) -> Result<Hash256> {
    Ok(match &entry.withdrawal_execution_address {
        Some(address_hex) => {
            let address = hex::decode(address_hex).map_err(|e| {
                anyhow!(
                    "Invalid withdrawal_execution_address {}: {:?}",
                    &address_hex,
                    e
                )
            })?;
            if address.len() != 20 {
                return Err(anyhow!(
                    "withdrawal_execution_address must be 20 bytes: {}",
                    address_hex
                ));
            }
            eth1_withdrawal_credentials(&address, spec)
        }
        None => bls_withdrawal_credentials(
            &keypair_from_seed(seed, index, KeyType::Withdrawal)?.pk,
            spec,
        ),
    })
}

fn exec_json_block_to_execution_payload_header<T: EthSpec>(
    eth1_block: ethers_core::types::Block<ethers_core::types::Transaction>,
) -> Result<ExecutionPayloadHeaderCapella<T>> {
    let transactions: Transactions<T> = eth1_block
        .transactions
        .iter()
        .map(|tx| tx.rlp().to_vec().into())
        .collect::<Vec<_>>()
        .into();

    let withdrawals: Withdrawals<T> = if let Some(el_withdrawals) = eth1_block.withdrawals {
        el_withdrawals
            .iter()
            .map(|withdrawal| Withdrawal {
                index: withdrawal.index.as_u64(),
                validator_index: withdrawal.validator_index.as_u64(),
                address: withdrawal.address.to_fixed_bytes().into(),
                amount: withdrawal.amount.as_u64(),
            })
            .collect::<Vec<_>>()
            .into()
    } else {
        <_>::default()
    };

    Ok(ExecutionPayloadHeaderCapella {
        parent_hash: ExecutionBlockHash::from_root(eth1_block.parent_hash.to_fixed_bytes().into()),
        fee_recipient: eth1_block
            .author
            .ok_or_else(|| anyhow!("no block.author"))?,
        state_root: eth1_block.state_root,
        receipts_root: eth1_block.receipts_root,
        logs_bloom: eth1_block
            .logs_bloom
            .ok_or_else(|| anyhow!("no block.logs_bloom"))?
            .to_fixed_bytes()
            .to_vec()
            .into(),
        prev_randao: eth1_block
            .mix_hash
            .ok_or_else(|| anyhow!("no block.mix_hash"))?,
        block_number: eth1_block
            .number
            .ok_or_else(|| anyhow!("no block.number"))?
            .as_u64(),
        gas_limit: eth1_block.gas_limit.as_u64(),
        gas_used: eth1_block.gas_used.as_u64(),
        timestamp: eth1_block.timestamp.as_u64(),
        extra_data: eth1_block.extra_data.to_vec().into(),
        base_fee_per_gas: Uint256::from_ssz_bytes(
            &eth1_block
                .base_fee_per_gas
                .ok_or_else(|| anyhow!("no block.base_fee_per_gas"))?
                .as_ssz_bytes(),
        )
        .map_err(|e| anyhow!("unable to convert base_fee_per_gas {e:?}"))?,
        block_hash: ExecutionBlockHash::from_root(
            eth1_block
                .hash
                .ok_or_else(|| anyhow!("no block.hash"))?
                .to_fixed_bytes()
                .into(),
        ),
        withdrawals_root: withdrawals.tree_hash_root(),
        transactions_root: transactions.tree_hash_root(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_from_seed_test() {
        let seed = seed_from_mnemonic(
            "obvious call slogan version awful elder where never price clump uniform humble",
        )
        .unwrap();
        // Signing: m/12381/3600/654/0/0
        assert_eq!(
            keypair_from_seed(&seed, 654, KeyType::Voting).unwrap().pk.as_hex_string(),
            "0x8b2cf47ad1ae4e62aedcb12439d458ed0921b65c0f822f163c1fb6218f0ccaa3346da0031aee5ce86a475bdd313be967",
            "voting key"
        );
        // Withdrawal: m/12381/3600/654/0
        assert_eq!(
            keypair_from_seed(&seed, 654, KeyType::Withdrawal).unwrap().pk.as_hex_string(),
            "0xaf7dff97aeecb9b3a92855d2c3a4276548f7f90aa482d3e59068de5a7c2b1d8eb39e4a6dc15a06083eb90876c1fabf11",
            "withdrawal key"
        );
    }

    fn run_cli_test<T: EthSpec>(testnet_dir: &str, mnemonics: Option<String>) -> BeaconState<T> {
        let count = 100;
        let mnemonics = mnemonics.unwrap_or(
            "
- mnemonic: obvious call slogan version awful elder where never price clump uniform humble
  count: 100"
                .to_string(),
        );

        run(Cli {
            testnet_dir: testnet_dir.to_string(),
            output: None,
            eth1_block: None,
            mnemonics,
        })
        .unwrap();

        let eth2_network_config = Eth2NetworkConfig::load(testnet_dir.into()).unwrap();
        let spec = &eth2_network_config.chain_spec::<T>().unwrap();

        let state = BeaconState::<T>::from_ssz_bytes(
            &fs::read(Path::new(testnet_dir).join("genesis.ssz")).unwrap(),
            spec,
        )
        .unwrap();

        // Sanity check state has correct data
        assert_eq!(state.validators().len(), count, "wrong validators.len()");
        assert_eq!(state.balances().len(), count, "wrong balances.len()");

        state
    }

    #[test]
    fn testnet_dir_mainnet() {
        run_cli_test::<MainnetEthSpec>("tests/testnet_dir_mainnet", None);
    }

    #[test]
    fn testnet_dir_minimal() {
        run_cli_test::<MinimalEthSpec>("tests/testnet_dir_minimal", None);
    }

    #[test]
    fn testnet_dir_gnosis() {
        run_cli_test::<GnosisEthSpec>("tests/testnet_dir_gnosis", None);
    }

    #[test]
    fn testnet_dir_minimal_execution_withdrawal() {
        let address = "0xabababababababababababababababababababab";
        let withcred = "0x010000000000000000000000abababababababababababababababababababab";
        let state = run_cli_test::<MinimalEthSpec>(
            "tests/testnet_dir_minimal",
            Some(format!(
                "
- mnemonic: obvious call slogan version awful elder where never price clump uniform humble
  count: 100
  withdrawal_execution_address: {address}
",
            )),
        );

        let expected_withdrawal_credentials = hex::decode(withcred).unwrap();
        for validator in state.validators() {
            assert_eq!(
                validator.withdrawal_credentials.as_bytes(),
                &expected_withdrawal_credentials
            );
        }
    }

    #[test]
    fn test_exec_json_block_to_execution_payload_header() {
        assert_eq!(
            GnosisEthSpec::max_withdrawals_per_payload(),
            8,
            "wrong GnosisEthSpec::max_withdrawals_per_payload"
        );

        let expected_header =
            fs::read_to_string("tests/latest_execution_payload_header_13412599.json").unwrap();
        let eth1_block_json = fs::read_to_string("tests/block_exec_32096192.json").unwrap();
        let eth1_block: ethers_core::types::Block<ethers_core::types::Transaction> =
            serde_json::from_str(&eth1_block_json).unwrap();

        let header =
            exec_json_block_to_execution_payload_header::<GnosisEthSpec>(eth1_block).unwrap();

        let header = serde_json::to_string_pretty(&header).unwrap();
        pretty_assertions::assert_eq!(header, expected_header);
    }
}
