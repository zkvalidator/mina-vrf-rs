use clap::Clap;
use graphql_client::*;
use reqwest;
use std::error::Error;
use MacTypes_sys::{UInt32, UInt64};

// The paths are relative to the directory where your `Cargo.toml` is located.
// Both json and the GraphQL schema language are supported as sources for the schema
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "contrib/regen_schema.graphql",
    query_path = "contrib/query.graphql"
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
}

/// A subcommand for generating key pair
#[derive(Clap)]
struct KeygenOpts {
    /// Output public key file
    #[clap(short = "p", long = "pub", default_value = "pub.key")]
    pubkey: String,
    /// Output private key file
    #[clap(short = "v", long = "prv", default_value = "prv.key")]
    prvkey: String,
}

fn main() {
    ::std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Keygen(o) => {
            key_gen(o);
        }
    }
}

fn key_gen(opts: KeygenOpts) {
    unimplemented!()
}
