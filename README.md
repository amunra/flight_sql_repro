# Flight SQL - DictId Schema Serialization Issue - FlatBuf ParseError
See: https://github.com/apache/arrow-rs/discussions/4678

## Steps to reproduce

### Run the server

```bash
cd flight-sql-server-rs
cargo run
```
```
   Compiling flight-sql-server-rs v0.1.0 (/Users/adam/github/flight_sql_repro/flight-sql-server-rs)
    Finished dev [unoptimized + debuginfo] target(s) in 1.04s
     Running `target/debug/flight-sql-server-rs`
Listening on 0.0.0.0:50051
```

### Run the client

```bash
cd flight-sql-client-rs
cargo run
```
```
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/flight-sql-client-rs`
[2023-08-14T09:33:13Z INFO  flight_sql_client_rs] Connected to gRPC channel: Channel, about to prepare query: "fake"
[2023-08-14T09:33:13Z ERROR flight_sql_client_rs] Failed deserializing batch: ParseError("Unable to convert flight info to a message: Type `i64` at position 116 is unaligned.\n\twhile verifying table field `id` at position 116\n\twhile verifying table field `dictionary` at position 84\n\twhile verifying vector element 2 at position 64\n\twhile verifying table field `fields` at position 48\n\t while verifying union variant `MessageHeader::Schema` at position 28\n\twhile verifying table field `header` at position 28\n\n")
```