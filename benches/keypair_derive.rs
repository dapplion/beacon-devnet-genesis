use anyhow::{anyhow, Result};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use eth2_wallet::bip39::Seed;
use eth2_wallet::bip39::{Language, Mnemonic};
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType};
use types::{Keypair, SecretKey};

fn keypair_from_seed(seed: &Seed, index: u32, key_type: KeyType) -> Result<Keypair> {
    let (secret, _) = recover_validator_secret_from_mnemonic(seed.as_bytes(), index, key_type)
        .map_err(|e| anyhow!("Unable to recover validator keys: {:?}", e))?;
    let sk = SecretKey::deserialize(secret.as_bytes())
        .map_err(|e| anyhow!("Invalid secret key bytes: {:?}", e))?;
    let pk = sk.public_key();
    Ok(Keypair::from_components(pk, sk))
}

// benches/crypto_benchmark.rs
fn keypair_from_seed_benchmark(c: &mut Criterion) {
    let mnemonic = "obvious call slogan version awful elder where never price clump uniform humble";
    let seed = Seed::new(
        &Mnemonic::from_phrase(mnemonic, Language::English).unwrap(),
        "",
    );

    c.bench_function("keypair_from_seed", |b| {
        b.iter(|| keypair_from_seed(black_box(&seed), black_box(0), black_box(KeyType::Voting)))
    });
}

criterion_group!(benches, keypair_from_seed_benchmark);
criterion_main!(benches);
