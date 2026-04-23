use crate::error::ApexError;

/// Credit-based flow control window (like QUIC's MAX_DATA / MAX_STREAM_DATA).
/// The sender may not transmit beyond `limit` total bytes.
pub struct FlowWindow {
    /// Total bytes the remote has permitted us to send.
    limit: u64,
    /// Total bytes we have consumed (sent or received).
    consumed: u64,
}

impl FlowWindow {
    pub fn new(initial_limit: u64) -> Self {
        Self { limit: initial_limit, consumed: 0 }
    }

    /// Try to reserve `n` bytes. Returns Ok(()) if within limit.
    pub fn reserve(&mut self, n: u64) -> Result<(), ApexError> {
        if self.consumed + n > self.limit {
            Err(ApexError::FlowControlBlocked {
                available: self.limit.saturating_sub(self.consumed),
                requested: n,
            })
        } else {
            self.consumed += n;
            Ok(())
        }
    }

    /// Remote has extended the limit.
    pub fn update_limit(&mut self, new_limit: u64) {
        if new_limit > self.limit {
            self.limit = new_limit;
        }
    }

    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }
}
