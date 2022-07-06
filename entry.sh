#!/bin/bash

set -e

for i in $(seq "$@"); do echo $i; RUST_LOG=info end-to-end-test 2> data/run$i.log ; done
python3 timings/stat.py
