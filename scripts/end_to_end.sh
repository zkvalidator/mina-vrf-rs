#!/bin/bash -xe

PUBKEY=$1
EPOCH=$2

cargo run --release -- batch-generate-witness --pub $PUBKEY --epoch $EPOCH > requests
cat requests | mina advanced vrf batch-generate-witness --privkey-path /keys/my-wallet | sed 's/Using password from environment variable CODA_PRIVKEY_PASS//g' > witnesses
cat witnesses | cargo run --release -- batch-patch-witness --pub $PUBKEY --epoch $EPOCH > patches
cat patches | mina advanced vrf batch-check-witness | sed 's/Using password from environment variable CODA_PRIVKEY_PASS//g' > check
cat check | cargo run --release -- batch-check-witness --pub $PUBKEY --epoch $EPOCH
