FROM rust

WORKDIR /usr/src/zswap

RUN rustup default nightly

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin
RUN mkdir bin
RUN echo "fn main() {}" > src/bin/end-to-end-test.rs
RUN echo "" > src/lib.rs
RUN cargo +nightly install --bin end-to-end-test --path .

COPY . .
RUN touch src/bin/end-to-end-test.rs
RUN touch src/lib.rs

VOLUME /usr/src/zswap/data

RUN cargo +nightly install --bin end-to-end-test --path .

RUN chmod +x entry.sh
ENTRYPOINT ["./entry.sh"]
