//! Traffic Morphing and Metadata Defense logic.

use rand::{thread_rng, Rng};
use tokio::time::{sleep, Duration};

/// Generates 'Chaff' packets to maintain a constant-rate traffic signature.
pub async fn send_chaff_stream(tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    loop {
        // We create the RNG inside the loop but before the await.
        let (jitter, chaff_payload) = {
            let mut rng = thread_rng();
            let j = rng.gen_range(50..150);
            let size = rng.gen_range(64..512);
            let mut payload = vec![0u8; size];
            rng.fill(&mut payload[..]);
            (j, payload)
        }; // rng is dropped here, so it's not held across the await below.

        sleep(Duration::from_millis(jitter)).await;

        let frame = crate::gsp::GspFrame::new(
            crate::gsp::MsgType::Chaff,
            chaff_payload
        );

        if tx.send(frame.to_bytes()).await.is_err() {
            break; // Stream closed
        }
    }
}