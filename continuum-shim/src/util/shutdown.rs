//! Graceful shutdown coordination.
//!
//! This module is prepared for future daemon integration.

#![allow(dead_code)]

use tokio::sync::broadcast;

/// Shutdown signal that can be cloned and awaited.
#[derive(Clone)]
pub struct ShutdownSignal {
    sender: broadcast::Sender<()>,
}

impl ShutdownSignal {
    /// Wait for the shutdown signal.
    pub async fn recv(&self) {
        let mut receiver = self.sender.subscribe();
        let _ = receiver.recv().await;
    }
}

/// Shutdown coordinator that can send shutdown signals.
pub struct ShutdownCoordinator {
    sender: broadcast::Sender<()>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { sender }
    }

    /// Get a signal receiver.
    pub fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            sender: self.sender.clone(),
        }
    }

    /// Trigger shutdown.
    pub fn shutdown(&self) {
        let _ = self.sender.send(());
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
