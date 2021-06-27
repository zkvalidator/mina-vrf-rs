use anyhow::{anyhow, Result};
use clap::Clap;
use graphql_client::*;

// TODO: inplement these type (ser, deser, from...)
type UInt32 = String;
type UInt64 = String;

// The paths are relative to the directory where your `Cargo.toml` is located.
// Both json and the GraphQL schema language are supported as sources for the schema
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "contrib/regen_schema.graphql",
    query_path = "contrib/query.graphql",
    response_derives = "Debug,Serialize,PartialEq"
)]
pub struct StakingData;

/// mina-vrf-rs client
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate a key pair
    Keygen(KeygenOpts),
    /// Query StakingData
    GetStakingData(GetStakingDataOpts),
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

/// A subcommand for generating key pair
#[derive(Clap)]
struct GetStakingDataOpts {
    /// Graphql endpoint URL
    #[clap(
        short = "e",
        long = "endpoint",
        default_value = "http://localhost:3085/graphql"
    )]
    endpoint: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Keygen(o) => match key_gen(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("keygen successfully!");
            }
        },
        SubCommand::GetStakingData(o) => match get_staking_data(o).await {
            Err(e) => log::error!("{}", e),
            _ => {
                log::info!("query successfully!");
            }
        },
    }
}

async fn key_gen(_opts: KeygenOpts) -> Result<()> {
    unimplemented!()
}

async fn get_staking_data(opts: GetStakingDataOpts) -> Result<()> {
    let request_body = StakingData::build_query(staking_data::Variables {});

    let client = reqwest::Client::new();
    let /*mut*/ res = client
        .post(opts.endpoint)
        .json(&request_body)
        .send()
        .await?;
    let response_body: Response<staking_data::ResponseData> = res.json().await?;
    log::debug!("{:#?}", response_body);
    if let Some(es) = response_body.errors {
        for e in es {
            log::error!("{}", e);
        }
        return Err(anyhow!("response_body contains errors"));
    }

    let best_chain = match &response_body.data {
        None => return Err(anyhow!("response_body data is empty")),
        Some(data) => match &data.best_chain {
            None => return Err(anyhow!("best_chain is None")),
            Some(best_chain) => match best_chain.len() == 1 {
                false => return Err(anyhow!("should only have 1 best_chain")),
                true => &best_chain[0],
            },
        },
    };
    let staking_epoch_data = &best_chain.protocol_state.consensus_state.staking_epoch_data;
    let seed = &staking_epoch_data.seed;
    let total_currency = &staking_epoch_data.ledger.total_currency;

    Ok(())
}
