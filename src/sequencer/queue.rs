//! Entry queue and sequencer with batching.
//!
//! Entries are queued and batched together before being assigned sequential indices.
//! This improves throughput by reducing database round-trips.

use crate::error::{Error, Result};
use crate::storage::Database;
use crate::types::{Entry, LogIndex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Configuration for the sequencer.
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// Maximum number of entries per batch.
    pub batch_max_size: usize,
    /// Maximum time to wait before flushing a batch.
    pub batch_max_age: Duration,
    /// Channel buffer size for incoming entries.
    pub channel_size: usize,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            batch_max_size: 256,
            batch_max_age: Duration::from_secs(1),
            channel_size: 1024,
        }
    }
}

/// Request to sequence an entry.
struct SequenceRequest {
    entry: Entry,
    response: oneshot::Sender<Result<LogIndex>>,
}

/// Entry sequencer that batches entries for efficient index assignment.
#[derive(Clone)]
pub struct Sequencer {
    sender: mpsc::Sender<SequenceRequest>,
}

impl Sequencer {
    /// Create a new sequencer.
    ///
    /// Returns the sequencer handle and a future that runs the sequencer loop.
    pub fn new(
        db: Database,
        config: SequencerConfig,
    ) -> (Self, impl std::future::Future<Output = ()>) {
        let (sender, receiver) = mpsc::channel(config.channel_size);
        let sequencer = Self { sender };
        let worker = SequencerWorker {
            db,
            config,
            receiver,
        };
        (sequencer, worker.run())
    }

    /// Add an entry to the log.
    ///
    /// Returns the assigned index once the entry has been sequenced.
    pub async fn add(&self, entry: Entry) -> Result<LogIndex> {
        let (tx, rx) = oneshot::channel();
        let request = SequenceRequest {
            entry,
            response: tx,
        };

        self.sender
            .send(request)
            .await
            .map_err(|_| Error::Internal("sequencer channel closed".into()))?;

        rx.await
            .map_err(|_| Error::Internal("sequencer response dropped".into()))?
    }
}

/// Background worker that processes the entry queue.
struct SequencerWorker {
    db: Database,
    config: SequencerConfig,
    receiver: mpsc::Receiver<SequenceRequest>,
}

impl SequencerWorker {
    async fn run(mut self) {
        let mut batch: Vec<SequenceRequest> = Vec::with_capacity(self.config.batch_max_size);
        let mut batch_deadline: Option<Instant> = None;

        loop {
            let timeout = batch_deadline
                .map(|d| d.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::MAX);

            tokio::select! {
                // Wait for new entries
                request = self.receiver.recv() => {
                    match request {
                        Some(req) => {
                            // Set batch deadline on first entry
                            if batch.is_empty() {
                                batch_deadline = Some(Instant::now() + self.config.batch_max_age);
                            }

                            batch.push(req);

                            // Flush if batch is full
                            if batch.len() >= self.config.batch_max_size {
                                self.flush_batch(&mut batch).await;
                                batch_deadline = None;
                            }
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !batch.is_empty() {
                                self.flush_batch(&mut batch).await;
                            }
                            return;
                        }
                    }
                }
                // Flush on timeout
                _ = tokio::time::sleep(timeout), if !batch.is_empty() => {
                    self.flush_batch(&mut batch).await;
                    batch_deadline = None;
                }
            }
        }
    }

    async fn flush_batch(&self, batch: &mut Vec<SequenceRequest>) {
        if batch.is_empty() {
            return;
        }

        tracing::debug!("Flushing batch of {} entries", batch.len());

        // Extract entries
        let entries: Vec<Entry> = batch.iter().map(|r| r.entry.clone()).collect();

        // Sequence entries in the database
        let result = self.db.sequence_entries(entries).await;

        // Drain the batch and send responses
        let requests: Vec<SequenceRequest> = std::mem::take(batch);

        match result {
            Ok(sequenced) => {
                for (req, seq_entry) in requests.into_iter().zip(sequenced.into_iter()) {
                    let _ = req.response.send(Ok(seq_entry.index()));
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                for req in requests {
                    let _ = req.response.send(Err(Error::Internal(err_msg.clone())));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a database connection
    // In a real implementation, we'd use a mock or test database

    #[test]
    fn test_config_defaults() {
        let config = SequencerConfig::default();
        assert_eq!(config.batch_max_size, 256);
        assert_eq!(config.batch_max_age, Duration::from_secs(1));
    }
}
