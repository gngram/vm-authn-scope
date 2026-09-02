//! Notification registry for broadcasting server events to connected agents.

use authn_scope_proto::wire::AgentResponse;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

pub type NotificationSender = mpsc::UnboundedSender<AgentResponse>;

#[derive(Default, Clone)]
pub struct NotificationRegistry {
    subscribers: Arc<Mutex<Vec<NotificationSender>>>,
}

impl NotificationRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn register(&self, sender: NotificationSender) {
        let mut subs = self.subscribers.lock().await;
        subs.push(sender);
        info!(total_subscribers = subs.len(), "Registered agent notification subscriber");
    }

    pub async fn notify_time_sync(&self) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = AgentResponse::TimeSyncNotification { timestamp };

        let mut subs = self.subscribers.lock().await;
        let initial_count = subs.len();
        subs.retain(|sender| sender.send(msg.clone()).is_ok());
        info!(
            timestamp,
            notified = subs.len(),
            initial_count,
            "Broadcasted time sync notification to agents"
        );
    }
}
