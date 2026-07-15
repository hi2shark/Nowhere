use super::*;

impl UnauthenticatedAdmission {
    pub(in crate::portal) fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .total
    }
}
