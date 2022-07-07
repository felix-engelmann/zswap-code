# zswap-code

This repository contains a reference implementation for the paper "Zswap: zk-SNARK Based Non-Interactive Multi-Asset Swaps" which provides a mechanism for adding multi-asset support together with atomic swaps on top of zcash-like cryptocurrency.
We also provide the benchmarks that measure the time of the main functions in zswap, such as generating and verifying proofs, or merging transactions.
To run the benchmarks (for Zswap and Mock Sapling), see the sections below.
For the purpose of comparison, we also include an implementation of Zcash, which we call "Mock Sapling" (since it has some differences from the original ZCash Sapling) -- to run the benchmarks for Mock Sapling, see the last section of this readme.


## Building and Running


To run the project on a UNIX-based system, you need a nightly version of [rust](https://rust-lang.org) installed. This can be done by first installing rust's toolchain manager, `rustup`, by following its [installation instructions](https://rust-lang.org/tools/install), and running the following in the repository directory:

```console
$ rustup update
$ rustup toolchain install nightly
$ rustup override set nightly
```

You also need `pkg-config` and `openssl` header files available for compilation.

Then, the end-to-end test, which provide an overview of the high-level function timings, can be run with:

```console
$ RUST_LOG=info cargo run --bin end-to-end-test --release
```

## Running in Docker

Another way to run the timing tests is to use docker.

Build the image with

```console
$ sudo docker build . -t zswap
```

The `zswap` image is then locally available and requires a parameter of number of repetition. Here is an example with 3 runs and the statistics.

```console
$ sudo docker run --rm -it zswap -- 3
1
2
3
Homomorphic commitment took                                0.904 -   0.025 +   3.741 ms
Spend proof took                                        1806.217 -  68.645 + 430.708 ms
Output proof took                                        861.858 -  22.279 +2205.524 ms
Randomness aggregation and transaction assembly took       0.025 -   0.011 +   0.058 ms
Commitment checks took                                     6.305 -   5.294 +   5.338 ms
Spend proof verify took                                    6.747 -   1.101 +   3.575 ms
Output proof verify took                                   8.068 -   0.902 +   0.273 ms
Consistency check took                                     0.002 -   0.001 +   0.003 ms
Merging signature and tx took                              0.048 -   0.017 +   0.033 ms
```

## Timing measurements

To reproduce the timing measurements used for the figure in the paper, first generate 30 samples

```console
$ mkdir data
$ for i in $(seq 30); do echo $i; RUST_LOG=info cargo +nightly run --release --bin end-to-end-test 2> data/run$i.log ; done
```

Then you can analyse them e.g. with the python script in `timings/stat.py`

```console
$ python3 timings/stat.py
```

which outputs the median, min and max time for each measurement.

## Measurements Description

We measure duration of the following procedures:
- Generating and verifying spend and output proofs (NIZK proofs attached to input nullifiers and output notes)
- Creating commitments and verifying their homomorphic sum in the transaction -- we use vector Pedersen commitments with bases created as hashes of types.
- Transaction assembly and randomness aggregation -- creating the transaction without the proofs (which are the heavy part).
- Merging signatures and transactions -- performing the atomic swap itself -- is cheap because it amounts to concatenating transactions and summing the joint randomness.

More details on the benchmarks can be found in `src/protocol.rs`.

## Mock sapling

Our mock sapling implementation requires code changes. These can be applied by running `git apply mock-sapling.patch`, and then run as before. The zswap implementation can be switched back to by running `git checkout .`.
