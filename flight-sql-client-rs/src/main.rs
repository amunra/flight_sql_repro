use arrow_flight::decode::FlightRecordBatchStream;
use arrow_flight::error::FlightError;
use arrow_flight::sql::client::FlightSqlServiceClient;
use futures::{StreamExt, TryStreamExt};
use log::{error, info};
use std::error::Error;
use tonic::transport::Channel;

#[tokio::main]
async fn async_main(query: String) -> Result<(), Box<dyn Error>> {
    let uri = "grpc+tcp://localhost:50051".parse()?;
    let token = "uuid_token";
    let start = std::time::Instant::now();
    let channel = Channel::builder(uri).connect().await?;
    info!("Connected to gRPC channel: {channel:?}, about to prepare query: {query:?}");
    let mut client = FlightSqlServiceClient::new(channel);
    client.set_token(token.to_string());
    let mut prepared = client.prepare(query, None).await?;
    let info = prepared.execute().await?;
    let ticket = info
        .endpoint
        .get(0)
        .expect("endpoint defined")
        .ticket
        .as_ref()
        .expect("ticked defined")
        .clone();
    info!("Got ticket: {ticket:?}");

    // This API I don't understand. What am I supposed to do with `FlightData`?
    let response_stream = client.do_get(ticket).await?;
    let mut response_stream =
        FlightRecordBatchStream::new_from_flight_data(response_stream.map_err(FlightError::Tonic));
    let mut batch_count = 0usize;
    let mut n_rows = 0usize;
    while let Some(batch) = response_stream.next().await {
        if batch.is_err() {
            error!("Batch {batch_count} errored");
        }
        let batch = batch?;
        n_rows += batch.num_rows();
        batch_count += 1;
    }
    let end = std::time::Instant::now();
    let elapsed = end - start;
    let rows_sec = n_rows as f64 / elapsed.as_secs_f64();
    info!(
        "Got {n_rows} rows back as {batch_count} batches, took {elapsed:?} ({rows_sec} rows/sec)"
    );
    Ok(())
}

fn main() {
    std::env::set_var("RUST_LOG", "trace");
    env_logger::init();

    let query = "fake".to_string();

    if let Err(err) = async_main(query) {
        error!("Failed deserializing batch: {err:?}");
    }
}
