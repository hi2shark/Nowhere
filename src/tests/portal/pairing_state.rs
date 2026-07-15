use super::*;

impl QuicUdpReceiver {
    pub(in crate::portal) fn new_without_barrier(
        receiver: mpsc::Receiver<crate::portal::conn::QueuedDatagram>,
        ready: Arc<AtomicBool>,
        on_drop: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            receiver,
            ready,
            ready_requests: None,
            on_drop: Some(Box::new(on_drop)),
        }
    }
}
