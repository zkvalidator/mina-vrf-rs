use anyhow::{anyhow, bail, Result};
use clap::Clap;
use graphql_client::*;
use reqwest::IntoUrl;
use rust_decimal::Decimal;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

// TODO: inplement these type (ser, deser, from...)
type UInt32 = String;
type UInt64 = String;
type PublicKey = String;

const NUM_SLOTS_IN_EPOCH: usize = 7140;
const DIGITS_AFTER_DECIMAL_POINT: u32 = 9;
const MINA_EXPLORER_ENDPOINT: &str = "https://graphql.minaexplorer.com";

// The paths are relative to the directory where your `Cargo.toml` is located.
// Both json and the GraphQL schema language are supported as sources for the schema
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "contrib/regen_schema.graphql",
    query_path = "contrib/query.graphql",
    response_derives = "Debug,Serialize,PartialEq"
)]
pub struct StakingData;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "contrib/regen_schema.graphql",
    query_path = "contrib/query.graphql",
    response_derives = "Debug,Serialize,PartialEq"
)]
pub struct Account;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "contrib/explorer_regen_schema.graphql",
    query_path = "contrib/explorer_query.graphql",
    response_derives = "Debug,Serialize,PartialEq"
)]
pub struct StakingDataExplorer;

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
        default_value = "http://localhost:3085/graphql"
    )]
    endpoint: String,
    /// User public key string
    #[clap(short = "p", long = "pub")]
    pubkey: String,
    #[clap(short = "n", long = "epoch")]
    epoch: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchGenerateWitnessSingleRequest {
    global_slot: String,
    epoch_seed: String,
    delegator_index: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchPatchWitnessSingleVrfThresholdRequest {
    delegated_stake: String,
    total_stake: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchPatchWitnessSingleRequest {
    message: BatchGenerateWitnessSingleRequest,
    public_key: String,
    c: String,
    s: String,
    #[serde(rename = "ScaledMessageHash")]
    scaled_message_hash: Vec<String>,
    vrf_threshold: Option<BatchPatchWitnessSingleVrfThresholdRequest>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchCheckWitnessSingleRequest {
    message: BatchGenerateWitnessSingleRequest,
    public_key: String,
    c: String,
    s: String,
    #[serde(rename = "ScaledMessageHash")]
    scaled_message_hash: Vec<String>,
    vrf_threshold: BatchPatchWitnessSingleVrfThresholdRequest,
    vrf_output: String,
    vrf_output_fractional: f64,
    threshold_met: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct LedgerAccountJson {
    pk: String,
    balance: String,
    delegate: String,
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

async fn batch_generate_witness(opts: VRFOpts) -> Result<()> {
    let request_body = StakingData::build_query(staking_data::Variables {});
    let data: staking_data::ResponseData = graphql_query(&opts.endpoint, &request_body).await?;

    let best_chain = match &data.best_chain {
        None => bail!("best_chain is None"),
        Some(best_chain) => match best_chain.len() == 1 {
            false => bail!("should only have 1 best_chain"),
            true => &best_chain[0],
        },
    };
    let staking_epoch_data = &best_chain.protocol_state.consensus_state.staking_epoch_data;
    let epoch = &best_chain.protocol_state.consensus_state.epoch;
    let (seed, total_currency, delegators_indices) = if epoch != &opts.epoch.to_string() {
        let url = format!(
            "https://raw.githubusercontent.com/zkvalidator/mina-vrf-rs/main/epochs/{}.json",
            opts.epoch
        );
        let request_body = StakingData::build_query(staking_data::Variables {});
        let data: staking_data::ResponseData =
            graphql_query(MINA_EXPLORER_ENDPOINT, &request_body).await?;

        let ledger: Vec<LedgerAccountJson> =
            serde_json::from_slice(&reqwest::get(url).await?.bytes().await?.to_vec()).unwrap();

        let delegators: HashMap<String, i64> = ledger
            .iter()
            .enumerate()
            .map(|(i, a)| (a.pk.clone(), i as i64))
            .collect();

        let delegators_indices = ledger
            .iter()
            .filter(|a| a.delegate == opts.pubkey)
            .map(|a| delegators[&a.pk])
            .collect::<Vec<_>>();

        let seed = &staking_epoch_data.seed;
        let total_currency = &staking_epoch_data.ledger.total_currency;
        (seed, total_currency, delegators_indices)
    } else {
        let seed = &staking_epoch_data.seed;
        let total_currency = &staking_epoch_data.ledger.total_currency;

        let request_body = Account::build_query(account::Variables {
            public_key: opts.pubkey,
        });

        let data: account::ResponseData = graphql_query(&opts.endpoint, &request_body).await?;
        let delegators = (match &data.account {
            None => bail!("delegators is None"),
            Some(account) => account.delegators.as_ref().unwrap(),
        })
        .into_iter()
        .map(|d| d.index.unwrap())
        .collect::<Vec<_>>();

        (seed, total_currency, delegators)
    };

    let slot = best_chain
        .protocol_state
        .consensus_state
        .slot_since_genesis
        .parse::<usize>()
        .unwrap();
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
            delegators_indices
                .iter()
                .map(move |index| BatchGenerateWitnessSingleRequest {
                    epoch_seed: staking_epoch_data.seed.clone(),
                    global_slot: slot.to_string(),
                    delegator_index: *index,
                })
                .into_iter()
        })
        .collect::<Vec<_>>();

    for request in requests {
        println!("{}", serde_json::to_string(&request).unwrap());
    }

    Ok(())
}

async fn batch_patch_witness(opts: VRFOpts) -> Result<()> {
    let request_body = StakingData::build_query(staking_data::Variables {});

    let client = reqwest::Client::new();
    let res = client
        .post(&opts.endpoint)
        .json(&request_body)
        .send()
        .await?;
    let response_body: Response<staking_data::ResponseData> = res.json().await?;
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }

    let best_chain = match &response_body.data {
        None => bail!("response_body data is empty"),
        Some(data) => match &data.best_chain {
            None => bail!("best_chain is None"),
            Some(best_chain) => match best_chain.len() == 1 {
                false => bail!("should only have 1 best_chain"),
                true => &best_chain[0],
            },
        },
    };
    let staking_epoch_data = &best_chain.protocol_state.consensus_state.staking_epoch_data;
    let seed = &staking_epoch_data.seed;
    let total_currency = {
        let mut currency = Decimal::from_str(&staking_epoch_data.ledger.total_currency).unwrap();
        currency.set_scale(DIGITS_AFTER_DECIMAL_POINT).unwrap();
        currency
    };

    let request_body = Account::build_query(account::Variables {
        public_key: opts.pubkey,
    });

    let client = reqwest::Client::new();
    let res = client
        .post(&opts.endpoint)
        .json(&request_body)
        .send()
        .await?;
    let response_body: Response<account::ResponseData> = res.json().await?;
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }
    let delegators = match &response_body.data {
        None => bail!("response_body data is empty"),
        Some(data) => match &data.account {
            None => bail!("delegators is None"),
            Some(account) => account.delegators.as_ref().unwrap(),
        },
    };

    let stdin = std::io::stdin();
    let stdin = stdin.lock();

    let deserializer = serde_json::Deserializer::from_reader(stdin);
    let iterator = deserializer.into_iter::<BatchPatchWitnessSingleRequest>();
    for item in iterator {
        let mut patched = item.unwrap();
        let mut balance = Decimal::from_str(
            &delegators
                .iter()
                .find(|d| d.index == Some(patched.message.delegator_index))
                .unwrap()
                .balance
                .total,
        )
        .unwrap();
        balance.set_scale(DIGITS_AFTER_DECIMAL_POINT).unwrap();
        patched.vrf_threshold = Some(BatchPatchWitnessSingleVrfThresholdRequest {
            delegated_stake: balance.to_string(),
            total_stake: total_currency.to_string(),
        });
        println!("{}", serde_json::to_string(&patched).unwrap());
    }

    Ok(())
}

async fn batch_check_witness(opts: VRFOpts) -> Result<()> {
    let request_body = StakingData::build_query(staking_data::Variables {});

    let client = reqwest::Client::new();
    let res = client
        .post(&opts.endpoint)
        .json(&request_body)
        .send()
        .await?;
    let response_body: Response<staking_data::ResponseData> = res.json().await?;
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }

    let best_chain = match &response_body.data {
        None => bail!("response_body data is empty"),
        Some(data) => match &data.best_chain {
            None => bail!("best_chain is None"),
            Some(best_chain) => match best_chain.len() == 1 {
                false => bail!("should only have 1 best_chain"),
                true => &best_chain[0],
            },
        },
    };
    let staking_epoch_data = &best_chain.protocol_state.consensus_state.staking_epoch_data;
    let seed = &staking_epoch_data.seed;
    let total_currency = &staking_epoch_data.ledger.total_currency;

    let request_body = Account::build_query(account::Variables {
        public_key: opts.pubkey,
    });

    let client = reqwest::Client::new();
    let res = client
        .post(&opts.endpoint)
        .json(&request_body)
        .send()
        .await?;
    let response_body: Response<account::ResponseData> = res.json().await?;
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }
    let delegators = match &response_body.data {
        None => bail!("response_body data is empty"),
        Some(data) => match &data.account {
            None => bail!("delegators is None"),
            Some(account) => account.delegators.as_ref().unwrap(),
        },
    };

    let stdin = std::io::stdin();
    let stdin = stdin.lock();

    let deserializer = serde_json::Deserializer::from_reader(stdin);
    let iterator = deserializer.into_iter::<BatchCheckWitnessSingleRequest>();
    let mut slot_to_vrf_results: HashMap<String, Vec<_>> = HashMap::new();
    for item in iterator {
        let e = item.unwrap();
        let slot = e.message.global_slot.clone();
        if !slot_to_vrf_results.contains_key(&slot) {
            slot_to_vrf_results.insert(slot.clone(), vec![]);
        }
        slot_to_vrf_results.get_mut(&slot).unwrap().push(e.clone());
    }
    let (first_slot_in_epoch, last_slot_in_epoch) = (
        NUM_SLOTS_IN_EPOCH * opts.epoch,
        (NUM_SLOTS_IN_EPOCH * (opts.epoch + 1) - 1),
    );

    let mut invalid_slots = vec![];
    let mut producing_slots = vec![];
    for slot in first_slot_in_epoch..=last_slot_in_epoch {
        if !slot_to_vrf_results.contains_key(&slot.to_string()) {
            invalid_slots.push(slot);
            continue;
        }
        let vrf_results = &slot_to_vrf_results[&slot.to_string()];
        if vrf_results.iter().any(|v| v.threshold_met) {
            producing_slots.push(slot - first_slot_in_epoch);
        }
        if !delegators.iter().all(|x| {
            vrf_results
                .iter()
                .find(|v| v.message.delegator_index == x.index.unwrap())
                .is_some()
        }) {
            invalid_slots.push(slot - first_slot_in_epoch);
            continue;
        }
    }

    println!("invalid slots: {:?}", invalid_slots);
    println!("producing slots: {:?}", producing_slots);

    Ok(())
}
