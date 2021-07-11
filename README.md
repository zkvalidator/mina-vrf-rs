# mina-vrf-rs

## Introduction

The Mina consensus algorithm uses a VRF to determine whether a block producer is eligible to produce a block at a specific slot. The VRF is produced with the block producer's public key.
A block producer can thus provably see and show whether they were eligible to produce blocks at a given slot, providing two interesting use cases:

* Knowing ahead of time at which slots a block can be produced, and use that knowledge to improve reliability
* Prove to delegators that you've performed adequately and produced all the blocks you should have produced

A caveat is that even though a BP is eligible to produce a block at a slot, multiple BPs can be, and so you're not guaranteed to win that slot.

## Workflow

`mina-vrf-rs` currently uses the `mina advanced vrf` set of commands. Therefore, it is mainly responsible for preparing the inputs and processing the outputs of those commands.

An example workflow - proving to a delegator your eligible blocks:

### Run by block producer

```
cargo run --release -- batch-generate-witness --pub B62qrHzjcZbYSsrcXVgGko7go1DzSEBfdQGPon5X4LEGExtNJZA4ECj --epoch 5 > requests
cat requests | mina advanced vrf batch-generate-witness --privkey-path /keys/my-wallet | grep -v CODA_PRIVKEY_PASS > witnesses
```

Send `witnesses` to delegator.

### Run by delegator

```
cat witnesses | cargo run --release -- batch-patch-witness --pub B62qrHzjcZbYSsrcXVgGko7go1DzSEBfdQGPon5X4LEGExtNJZA4ECj --epoch 5 > patches
cat patches | mina advanced vrf batch-check-witness | grep -v grep -v CODA_PRIVKEY_PASS > check
cat check | cargo run --release -- batch-check-witness --pub B62qrHzjcZbYSsrcXVgGko7go1DzSEBfdQGPon5X4LEGExtNJZA4ECj --epoch 5
```

This will let the delegator see an output of this form:
```
invalid slots: []
invalid local slots: []
producing slots: [35947, 36239, 36269, 36344, 36431, 36599, 36668, 36700, 36784, 36858, 36985, 37261, 37492, 37509, 37557, 37638, 37762, 37765, 38176, 38232, 38248, 38309, 38316, 38505, 38565, 38800, 38907, 38974, 39083, 39271, 39277, 39403, 39450, 39473, 39538, 39769, 39821, 40177, 40498, 40609, 40615, 40765, 41389, 41573, 42017, 42188, 42311, 42324, 42350, 42407, 42469, 42480, 42601, 42655, 42711]
producing local slots: [247, 539, 569, 644, 731, 899, 968, 1000, 1084, 1158, 1285, 1561, 1792, 1809, 1857, 1938, 2062, 2065, 2476, 2532, 2548, 2609, 2616, 2805, 2865, 3100, 3207, 3274, 3383, 3571, 3577, 3703, 3750, 3773, 3838, 4069, 4121, 4477, 4798, 4909, 4915, 5065, 5689, 5873, 6317, 6488, 6611, 6624, 6650, 6707, 6769, 6780, 6901, 6955, 7011]
```

## Future development

* Implement the cryptography internally, to not rely on the Mina node for the VRF evaluation and verification
* Have the ledger data verifiable, or cross-checked, rather than fetched in a trusted manner from Mina explorer and this repository
