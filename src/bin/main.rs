#![allow(clippy::enum_variant_names)]

use anyhow::{anyhow, Result};
use clap::Clap;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::str::FromStr;

use mina_graphql_rs::*;

/// mina-vrf-rs client
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    BatchGenerateWitness(VRFOpts),
    BatchPatchWitness(VRFOpts),
    BatchCheckWitness(VRFOpts),
}

/// A subcommand for generating key pair
#[derive(Clap)]
struct KeygenOpts {
    /// Output public key file
    #[clap(short = "p", long = "pub", default_value = "pub.key")]
    _pubkey: String,
    /// Output private key file
    #[clap(short = "v", long = "prv", default_value = "prv.key")]
    _prvkey: String,
}

#[derive(Clap)]
struct VRFOpts {
    /// Graphql endpoint URL
    #[clap(
        short = "e",
        long = "endpoint",
        default_value = DEFAULT_LOCAL_ENDPOINT
    )]
    endpoint: String,
    /// User public key string
    #[clap(short = "p", long = "pub")]
    pubkey: String,
    #[clap(short = "n", long = "epoch")]
    epoch: usize,
    #[clap(short = "o", long = "out-file", default_value = "-")]
    out_file: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BatchGenerateWitnessSingleRequest {
    pub global_slot: String,
    pub epoch_seed: String,
    pub delegator_index: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BatchPatchWitnessSingleVrfThresholdRequest {
    pub delegated_stake: String,
    pub total_stake: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BatchPatchWitnessSingleRequest {
    pub message: BatchGenerateWitnessSingleRequest,
    pub public_key: String,
    pub c: String,
    pub s: String,
    #[serde(rename = "ScaledMessageHash")]
    pub scaled_message_hash: Vec<String>,
    pub vrf_threshold: Option<BatchPatchWitnessSingleVrfThresholdRequest>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BatchCheckWitnessSingleRequest {
    pub message: BatchGenerateWitnessSingleRequest,
    pub public_key: String,
    pub c: String,
    pub s: String,
    #[serde(rename = "ScaledMessageHash")]
    pub scaled_message_hash: Vec<String>,
    pub vrf_threshold: BatchPatchWitnessSingleVrfThresholdRequest,
    pub vrf_output: String,
    pub vrf_output_fractional: f64,
    pub threshold_met: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckWitnessOutput {
    pub producing_slots: Vec<usize>,
    pub local_producing_slots: Vec<usize>,
    pub invalid_slots: Vec<usize>,
    pub local_invalid_slots: Vec<usize>,
}

fn open_buffered_file(path: &str) -> io::Result<Box<dyn Write>> {
    return if path == "-" {
        Ok(Box::new(BufWriter::new(io::stdout())))
    } else {
        Ok(Box::new(BufWriter::new(File::create(path)?)))
    };
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::BatchGenerateWitness(o) => match batch_generate_witness(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("Executed command successfully!");
            }
        },
        SubCommand::BatchPatchWitness(o) => match batch_patch_witness(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("Executed command successfully!");
            }
        },
        SubCommand::BatchCheckWitness(o) => match batch_check_witness(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("Executed command successfully!");
            }
        },
    }
}

async fn batch_generate_witness(opts: VRFOpts) -> Result<()> {
    let (seed, _, _, delegators) = get_staking_data(&opts.endpoint, opts.epoch as i64).await?;
    let delegators_indices = delegators
        .into_iter()
        .filter(|x| x.delegate == opts.pubkey)
        .map(|x| x.index)
        .collect::<Vec<_>>();

    let (first_slot_in_epoch, last_slot_in_epoch) = (
        NUM_SLOTS_IN_EPOCH * opts.epoch,
        (NUM_SLOTS_IN_EPOCH * (opts.epoch + 1) - 1),
    );
    log::debug!(
        "slot range: {}, {}",
        first_slot_in_epoch,
        last_slot_in_epoch
    );
    let requests = (first_slot_in_epoch..=last_slot_in_epoch)
        .flat_map(|slot| {
            let local_seed = seed.clone();
            let local_slot = slot.to_string();
            delegators_indices
                .iter()
                .map(move |index| BatchGenerateWitnessSingleRequest {
                    epoch_seed: local_seed.clone(),
                    global_slot: local_slot.clone(),
                    delegator_index: *index,
                })
                .into_iter()
        })
        .collect::<Vec<_>>();

    let mut f = open_buffered_file(&opts.out_file)?;
    for request in requests {
        f.write_all(format!("{}", serde_json::to_string(&request)?).as_bytes())?;
    }
    f.flush()?;

    Ok(())
}

async fn batch_patch_witness(opts: VRFOpts) -> Result<()> {
    let (_, total_currency, _, delegators) =
        get_staking_data(&opts.endpoint, opts.epoch as i64).await?;
    let total_currency = {
        let mut currency = Decimal::from_str(&total_currency)?;
        currency.set_scale(DIGITS_AFTER_DECIMAL_POINT)?;
        currency
    };

    let stdin = std::io::stdin();
    let stdin = stdin.lock();
    let mut f = open_buffered_file(&opts.out_file)?;

    let deserializer = serde_json::Deserializer::from_reader(stdin);
    let iterator = deserializer.into_iter::<BatchPatchWitnessSingleRequest>();
    for item in iterator {
        let mut patched = item?;
        let balance = Decimal::from_str(
            &delegators
                .iter()
                .find(|x| x.index == patched.message.delegator_index)
                .ok_or(anyhow!("can't find delegator"))?
                .balance,
        )?;
        patched.vrf_threshold = Some(BatchPatchWitnessSingleVrfThresholdRequest {
            delegated_stake: balance.to_string(),
            total_stake: total_currency.to_string(),
        });
        f.write_all(format!("{}", serde_json::to_string(&patched).unwrap()).as_bytes())?;
    }
    f.flush()?;

    Ok(())
}

async fn batch_check_witness(opts: VRFOpts) -> Result<()> {
    let stdin = std::io::stdin();
    let stdin = stdin.lock();

    let (_, _, _, delegators) = get_staking_data(&opts.endpoint, opts.epoch as i64).await?;

    let deserializer = serde_json::Deserializer::from_reader(stdin);
    let iterator = deserializer.into_iter::<BatchCheckWitnessSingleRequest>();
    let mut slot_to_vrf_results: HashMap<String, Vec<_>> = HashMap::new();
    for item in iterator {
        let e = item?;
        let slot = e.message.global_slot.clone();
        if !slot_to_vrf_results.contains_key(&slot) {
            slot_to_vrf_results.insert(slot.clone(), vec![]);
        }
        slot_to_vrf_results
            .get_mut(&slot)
            .ok_or(anyhow!("could not get mut"))?
            .push(e.clone());

        // TODO: write to output
        check_winners(opts.epoch, &opts.pubkey, e).await?;
    }
    let (first_slot_in_epoch, last_slot_in_epoch) = (
        NUM_SLOTS_IN_EPOCH * opts.epoch,
        (NUM_SLOTS_IN_EPOCH * (opts.epoch + 1) - 1),
    );

    let delegators_indices = delegators
        .into_iter()
        .filter(|x| x.delegate == opts.pubkey)
        .map(|x| x.index)
        .collect::<Vec<_>>();

    let mut invalid_slots = vec![];
    let mut local_invalid_slots = vec![];
    let mut producing_slots = vec![];
    let mut local_producing_slots = vec![];
    for slot in first_slot_in_epoch..=last_slot_in_epoch {
        if !slot_to_vrf_results.contains_key(&slot.to_string()) {
            invalid_slots.push(slot);
            local_invalid_slots.push(slot - first_slot_in_epoch);
            continue;
        }
        let vrf_results = &slot_to_vrf_results[&slot.to_string()];
        if vrf_results.iter().any(|v| v.threshold_met) {
            producing_slots.push(slot);
            local_producing_slots.push(slot - first_slot_in_epoch);
        }
        if !delegators_indices.iter().all(|x| {
            vrf_results
                .iter()
                .find(|v| v.message.delegator_index == *x)
                .is_some()
        }) {
            invalid_slots.push(slot);
            local_invalid_slots.push(slot - first_slot_in_epoch);
            continue;
        }
    }

    if invalid_slots.is_empty() {
        log::info!("no invalid slot");
    } else {
        log::error!("invalid slots: {:?}", invalid_slots);
    }
    if local_invalid_slots.is_empty() {
        log::info!("no invalid local slot");
    } else {
        log::error!("invalid local slots: {:?}", local_invalid_slots);
    }
    log::info!("producing slots: {:?}", producing_slots);
    log::info!("producing local slots: {:?}", local_producing_slots);

    let result = CheckWitnessOutput {
        producing_slots,
        local_producing_slots,
        invalid_slots,
        local_invalid_slots,
    };
    let mut f = open_buffered_file(&opts.out_file)?;
    f.write_all(serde_json::to_string(&result)?.as_bytes())?;
    f.flush()?;

    Ok(())
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct WinnerResult {
    our_blocks: Vec<i64>,
    others_blocks: Vec<i64>,
    blocks_we_miss: Vec<i64>,
}

async fn check_winners(
    epoch: usize,
    pubkey: &str,
    req: BatchCheckWitnessSingleRequest,
) -> Result<WinnerResult> {
    let blocks = get_epoch_blocks_winners_from_explorer(epoch as i64).await?;
    let mut winner_result = WinnerResult::default();

    for b in blocks {
        let block_height = b.block_height.as_ref().ok_or(anyhow!("no block_height"))?;
        log::info!("block {:?}", block_height);
        let winner = b
            .winner_account
            .as_ref()
            .ok_or(anyhow!("no winner_account"))?
            .public_key
            .as_ref()
            .ok_or(anyhow!("winner_account no public_key"))?;
        log::info!("winnerAccount {:?}", winner);

        if winner == pubkey {
            log::info!("block {:?} winner is ourself", block_height);
            winner_result.our_blocks.push(*block_height);
        } else {
            if is_threshold_met(&req) {
                log::warn!("we should produce block {:?} but we didn't", block_height);
                winner_result.blocks_we_miss.push(*block_height);
            } else {
                log::warn!("block {:?} belongs to others", block_height);
                winner_result.others_blocks.push(*block_height);
            }
        }
    }

    Ok(winner_result)
}

// (* Check if
//  vrf_output / 2^256 <= c * (1 - (1 - f)^(amount / total_stake))
// i.e.,
//  (1 - f)^amount <= (1 - (vrf_output / 2^256 / c))^total_stake
// *)
use mina_vrf_rs::params::{C, F};
use num::rational::BigRational;
use num::traits::*;
use num::BigInt;
fn is_threshold_met(req: &BatchCheckWitnessSingleRequest) -> bool {
    let vrf_output = BigInt::from_str(&req.vrf_output).unwrap();
    let amount = BigInt::from_str(&req.vrf_threshold.delegated_stake).unwrap();
    let total_stake = BigInt::from_str(&req.vrf_threshold.total_stake).unwrap();

    let one = BigRational::from(BigInt::from(1));
    let two = BigRational::from(BigInt::from(2));
    let c = BigRational::from(BigInt::from(C));
    let f = BigRational::from_float(F).unwrap();

    let lhs: BigRational = (one.clone() - f).pow(&amount);
    let rhs: BigRational = BigRational::from(one - (BigRational::from(vrf_output) / two.pow(256) / c)).pow(&total_stake);

    lhs <= rhs
}
