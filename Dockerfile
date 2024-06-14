FROM rust:1.79 as build

RUN cargo new doh-server
WORKDIR /doh-server

COPY Cargo.toml Cargo.lock .
RUN cargo build --release
RUN rm -rf src && rm -rf target/release/deps/doh-server
COPY ./src ./src
RUN cargo build --release
RUN ls -alh /doh-server/target/release

FROM debian
WORKDIR doh-server
COPY --from=build /doh-server/target/release/doh-server ./doh-server
COPY ./conf/default.toml ./conf/default.toml
CMD ["/doh-server/doh-server"]
