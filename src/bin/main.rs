#![allow(clippy::enum_variant_names)]

use anyhow::{anyhow, bail, Result};
use clap::Clap;
use graphql_client::*;
use reqwest::IntoUrl;
use rust_decimal::Decimal;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::str::FromStr;

use mina_vrf_rs::graphql::*;
use mina_vrf_rs::r#const::*;

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
                log::info!("command successfully!");
            }
        },
        SubCommand::BatchPatchWitness(o) => match batch_patch_witness(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("command successfully!");
            }
        },
        SubCommand::BatchCheckWitness(o) => match batch_check_witness(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("command successfully!");
            }
        },
    }
}

async fn graphql_query<U: IntoUrl, B: Serialize + ?Sized, R: DeserializeOwned>(
    endpoint: U,
    request_body: &B,
) -> Result<R> {
    let client = reqwest::Client::new();
    let res = client.post(endpoint).json(request_body).send().await?;
    let response_body: Response<R> = res.json().await?;
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }

    response_body.data.ok_or(anyhow!("response_body was none"))
}

async fn get_staking_data(
    endpoint: &str,
    epoch: i64,
) -> Result<(String, String, String, Vec<LedgerAccount>)> {
    let request_body = StakingData::build_query(staking_data::Variables {});
    let data: staking_data::ResponseData = graphql_query(endpoint, &request_body).await?;

    let best_chain = match &data.best_chain {
        None => bail!("best_chain is None"),
        Some(best_chain) => match best_chain.len() == 1 {
            false => bail!("should only have 1 best_chain"),
            true => &best_chain[0],
        },
    };
    let best_epoch = &best_chain.protocol_state.consensus_state.epoch;

    let (seed, total_currency, ledger_hash) = if best_epoch != &epoch.to_string() {
        let request_body =
            StakingDataExplorer::build_query(staking_data_explorer::Variables { epoch });
        let data: staking_data_explorer::ResponseData =
            graphql_query(MINA_EXPLORER_ENDPOINT, &request_body).await?;

        let explorer_staking_epoch_data = data.blocks[0]
            .as_ref()
            .ok_or(anyhow!("no block"))?
            .protocol_state
            .as_ref()
            .ok_or(anyhow!("no protocol state"))?
            .consensus_state
            .as_ref()
            .ok_or(anyhow!("no consensus state"))?
            .staking_epoch_data
            .as_ref()
            .ok_or(anyhow!("no staking epoch data"))?;

        let ledger = &explorer_staking_epoch_data
            .ledger
            .as_ref()
            .ok_or(anyhow!("no ledger"))?;
        let seed = explorer_staking_epoch_data
            .seed
            .as_ref()
            .ok_or(anyhow!("no seed"))?;
        let total_currency = &ledger
            .total_currency
            .as_ref()
            .ok_or(anyhow!("no total currency"))?;
        let ledger_hash = explorer_staking_epoch_data
            .ledger
            .as_ref()
            .ok_or(anyhow!("no ledger"))?
            .hash
            .as_ref()
            .ok_or(anyhow!("no hash"))?;

        (
            seed.clone(),
            total_currency.to_string(),
            ledger_hash.clone(),
        )
    } else {
        let staking_epoch_data = &best_chain.protocol_state.consensus_state.staking_epoch_data;
        let seed = &staking_epoch_data.seed;
        let total_currency = &staking_epoch_data.ledger.total_currency;
        let ledger_hash = &staking_epoch_data.ledger.hash;

        (seed.clone(), total_currency.clone(), ledger_hash.clone())
    };

    let url = format!(
        "https://raw.githubusercontent.com/zkvalidator/mina-vrf-rs/main/data/epochs/{}.json",
        ledger_hash,
    );

    let ledger: Vec<LedgerAccountJson> =
        serde_json::from_slice(&reqwest::get(url).await?.bytes().await?.to_vec())?;

    let delegators = extract_delegators(&ledger);

    Ok((seed, total_currency, ledger_hash, delegators))
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

    for request in requests {
        log::info!("{}", serde_json::to_string(&request)?);
    }

    Ok(())
}

fn extract_delegators(ledger: &[LedgerAccountJson]) -> Vec<LedgerAccount> {
    let delegators = ledger
        .into_iter()
        .enumerate()
        .map(|(i, a)| LedgerAccount {
            pk: a.pk.clone(),
            balance: a.balance.clone(),
            delegate: a.delegate.clone(),
            index: i as i64,
        })
        .collect();

    delegators
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
        log::info!("{}", serde_json::to_string(&patched).unwrap());
    }

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

    Ok(())
}
