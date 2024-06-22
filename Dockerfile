FROM rust:1.79 as build
WORKDIR /doh-server

COPY Cargo.toml Cargo.lock .
COPY ./src ./src
RUN cargo build --release

FROM debian
WORKDIR /doh-server
COPY --from=build /doh-server/target/release/doh-server ./doh-server
COPY ./conf/default.toml ./conf/default.toml
CMD ["/doh-server/doh-server"]
