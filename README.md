# zswap-code

To run the project, you need anightly version of rust. Then execute

    RUST_LOG=info cargo run --bin end-to-end-test --release
    
to get an overview of the high level function timings.

## Timing measurements

To reproduce the timing measurements used for the figure in the paper, first generate 30 samples

    mkdir data
    for i in $(seq 30); do echo $i; RUST_LOG=info cargo +nightly run --release --bin end-to-end-test 2> data/run$i.log ; done
    
Then you can analyse them e.g. with the python script in `timings/stat.py`

    python3 timings/stat.py
    
which outputs the median, min and max time for each measurement.
