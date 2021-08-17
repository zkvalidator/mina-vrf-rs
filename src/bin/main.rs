#![allow(clippy::enum_variant_names)]

use anyhow::{anyhow, Result};
use bigdecimal::{BigDecimal, ToPrimitive};
use blake2b_simd::Params;
use chrono::Duration;
use clap::Clap;
use mina_graphql_rs::*;
use num_bigint::{BigInt, Sign};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::str::FromStr;

const SLOT_TIME_MINUTES: i64 = 3;

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
    pub won_slots: Vec<usize>,
    pub local_won_slots: Vec<usize>,
    pub lost_slots: Vec<usize>,
    pub local_lost_slots: Vec<usize>,
    pub missed_slots: Vec<(usize, MissedBlockReason)>,
    pub local_missed_slots: Vec<(usize, MissedBlockReason)>,
    pub ambiguous_slots: Vec<(usize, Vec<SlotResult>)>,
    pub local_ambiguous_slots: Vec<(usize, Vec<SlotResult>)>,
}

fn open_buffered_file(path: &str) -> io::Result<Box<dyn Write>> {
    return if path == "-" {
        Ok(Box::new(BufWriter::new(io::stdout())))
    } else {
        Ok(Box::new(BufWriter::new(File::create(path)?)))
    };
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SlotResult {
    Won,
    Lost,
    Missed(MissedBlockReason),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MissedBlockReason {
    NotProducedOrPropagated,
    PropagatedTooLate(String, String),
    HeightTooOld(i64, i64),
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

#[allow(dead_code)]
fn vrf_output_to_fractional(vrf_output: &str) -> Result<f64> {
    let vrf_bytes = vrf_output_to_bytes(vrf_output)?;
    let vrf = BigDecimal::from((BigInt::from_bytes_le(Sign::Plus, &vrf_bytes), 0i64));
    let adjust = BigDecimal::from((BigInt::from(2).pow(253), 0i64));
    (vrf / adjust)
        .to_f64()
        .ok_or(anyhow!("should have converted decimal to float"))
}

fn vrf_output_to_bytes(vrf_output: &str) -> Result<Vec<u8>> {
    let bytes = bs58::decode(vrf_output).into_vec()?;
    if bytes.len() < 36 {
        return Err(anyhow!("not enough bytes in vrf output"));
    }
    Ok(bytes[3..35].to_vec())
}

fn vrf_output_to_digest_bytes(vrf_output: &str) -> Result<Vec<u8>> {
    let bytes = vrf_output_to_bytes(vrf_output)?;
    Ok(Params::new()
        .hash_length(32)
        .to_state()
        .update(&bytes)
        .finalize()
        .as_bytes()
        .to_vec())
}

fn compare_vrfs(v1: &[u8], v2: &[u8]) -> bool {
    for (i, v) in v1.iter().enumerate() {
        if v > &v2[i] {
            return true;
        } else if v < &v2[i] {
            return false;
        }
    }
    return false;
}

async fn analyze_slot(
    delegators_index_to_public_key: &HashMap<i64, String>,
    delegator_details: &BatchCheckWitnessSingleRequest,
    slot: i64,
    winners_for_epoch: &HashMap<i64, BlockResult>,
    blocks_for_creator_for_epoch: &HashMap<i64, BlockResult>,
) -> Result<SlotResult> {
    let delegator_public_key =
        &delegators_index_to_public_key[&delegator_details.message.delegator_index];

    let winners_exist = winners_for_epoch.contains_key(&slot);
    let saw_my_producer = blocks_for_creator_for_epoch.contains_key(&slot);
    if !winners_exist {
        if !saw_my_producer {
            let reason = MissedBlockReason::NotProducedOrPropagated;
            return Ok(SlotResult::Missed(reason));
        } else {
            let late = blocks_for_creator_for_epoch[&slot].received_time
                > (blocks_for_creator_for_epoch[&slot].date_time
                    + Duration::minutes(SLOT_TIME_MINUTES));
            if late {
                let my_producer_block = &blocks_for_creator_for_epoch[&slot];
                let reason = MissedBlockReason::PropagatedTooLate(
                    my_producer_block.date_time.to_rfc3339(),
                    my_producer_block.received_time.to_rfc3339(),
                );
                return Ok(SlotResult::Missed(reason));
            } else {
                return Ok(SlotResult::Lost);
            }
        }
    } else {
        let winner_for_slot = &winners_for_epoch[&slot];
        let my_producer_is_the_winner = &winner_for_slot.public_key == delegator_public_key;
        if my_producer_is_the_winner {
            return Ok(SlotResult::Won);
        } else {
            if saw_my_producer {
                let my_producer_block = &blocks_for_creator_for_epoch[&slot];
                let block_height_equal =
                    my_producer_block.block_height == winner_for_slot.block_height;
                if block_height_equal {
                    let winner_digest = vrf_output_to_digest_bytes(&winner_for_slot.vrf)?;
                    let our_digest = vrf_output_to_digest_bytes(&delegator_details.vrf_output)?;
                    if compare_vrfs(&our_digest, &winner_digest) {
                        let late = blocks_for_creator_for_epoch[&slot].received_time
                            > (blocks_for_creator_for_epoch[&slot].date_time
                                + Duration::minutes(SLOT_TIME_MINUTES));
                        if late {
                            let reason = MissedBlockReason::PropagatedTooLate(
                                my_producer_block.date_time.to_rfc3339(),
                                my_producer_block.received_time.to_rfc3339(),
                            );
                            return Ok(SlotResult::Missed(reason));
                        } else {
                            return Ok(SlotResult::Lost);
                        }
                    } else {
                        return Ok(SlotResult::Lost);
                    }
                } else {
                    let reason = MissedBlockReason::HeightTooOld(
                        my_producer_block.block_height,
                        winner_for_slot.block_height,
                    );
                    return Ok(SlotResult::Missed(reason));
                }
            } else {
                let winner_digest = vrf_output_to_digest_bytes(&winner_for_slot.vrf)?;
                let our_digest = vrf_output_to_digest_bytes(&delegator_details.vrf_output)?;
                if compare_vrfs(&our_digest, &winner_digest) {
                    let reason = MissedBlockReason::NotProducedOrPropagated;
                    return Ok(SlotResult::Missed(reason));
                } else {
                    return Ok(SlotResult::Lost);
                }
            }
        }
    }
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
    }
    let (first_slot_in_epoch, last_slot_in_epoch) = (
        NUM_SLOTS_IN_EPOCH * opts.epoch,
        (NUM_SLOTS_IN_EPOCH * (opts.epoch + 1) - 1),
    );

    let delegators_indices = delegators
        .iter()
        .filter(|x| x.delegate == opts.pubkey)
        .map(|x| x.index)
        .collect::<Vec<_>>();

    let delegators_index_to_public_key = delegators
        .into_iter()
        .filter(|x| x.delegate == opts.pubkey)
        .map(|x| (x.index, x.pk.clone()))
        .collect::<HashMap<_, _>>();

    let mut invalid_slots = vec![];
    let mut local_invalid_slots = vec![];
    let mut producing_slots = vec![];
    let mut local_producing_slots = vec![];
    let mut won_slots = vec![];
    let mut local_won_slots = vec![];
    let mut lost_slots = vec![];
    let mut local_lost_slots = vec![];
    let mut missed_slots = vec![];
    let mut local_missed_slots = vec![];
    let mut ambiguous_slots = vec![];
    let mut local_ambiguous_slots = vec![];

    let winners_for_epoch = get_winners_for_epoch(opts.epoch).await?;
    let blocks_for_creator_for_epoch =
        get_blocks_for_creator_for_epoch(opts.epoch, &opts.pubkey).await?;

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
        let results = vrf_results
            .iter()
            .filter(|v| v.threshold_met)
            .map(|delegator_details| {
                analyze_slot(
                    &delegators_index_to_public_key,
                    delegator_details,
                    slot as i64,
                    &winners_for_epoch,
                    &blocks_for_creator_for_epoch,
                )
            })
            .collect::<Vec<_>>();
        let results = futures::future::try_join_all(results).await?;
        if results.len() > 0 && results.iter().all(|r| r == &results[0]) {
            let result = &results[0];
            match result {
                SlotResult::Won => {
                    won_slots.push(slot);
                    local_won_slots.push(slot - first_slot_in_epoch);
                }
                SlotResult::Lost => {
                    lost_slots.push(slot);
                    local_lost_slots.push(slot - first_slot_in_epoch);
                }
                SlotResult::Missed(reason) => {
                    missed_slots.push((slot, reason.clone()));
                    local_missed_slots.push((slot - first_slot_in_epoch, reason.clone()));
                }
            }
            continue;
        }
        if results.iter().any(|r| r == &SlotResult::Won) {
            won_slots.push(slot);
            local_won_slots.push(slot - first_slot_in_epoch);
            continue;
        }

        if results.len() > 0 {
            ambiguous_slots.push((slot, results.clone()));
            local_ambiguous_slots.push((slot - first_slot_in_epoch, results.clone()));
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
    log::info!("won slots: {:?}", won_slots);
    log::info!("won local slots: {:?}", local_won_slots);
    log::info!("lost slots: {:?}", lost_slots);
    log::info!("lost local slots: {:?}", local_lost_slots);
    log::info!("missed slots: {:?}", missed_slots);
    log::info!("missed local slots: {:?}", local_missed_slots);
    log::info!("ambiguous slots: {:?}", ambiguous_slots);
    log::info!("ambiguous local slots: {:?}", local_ambiguous_slots);

    let result = CheckWitnessOutput {
        producing_slots,
        local_producing_slots,
        invalid_slots,
        local_invalid_slots,
        won_slots,
        local_won_slots,
        lost_slots,
        local_lost_slots,
        missed_slots,
        local_missed_slots,
        ambiguous_slots,
        local_ambiguous_slots,
    };
    let mut f = open_buffered_file(&opts.out_file)?;
    f.write_all(serde_json::to_string(&result)?.as_bytes())?;
    f.flush()?;

    Ok(())
}
