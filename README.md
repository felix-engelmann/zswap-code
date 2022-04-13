# zswap-code

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

## Mock sapling

Our mock sapling implementation requires code changes. These can be applied by running `git apply mock-sapling.patch`, and then run as before. The zswap implementation can be switched back to by running `git checkout .`.
