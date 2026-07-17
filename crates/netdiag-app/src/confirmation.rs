#[derive(Debug, Default)]
pub(super) struct TargetConfirmation<T> {
    armed: Option<T>,
}

impl<T: PartialEq> TargetConfirmation<T> {
    pub(super) fn is_armed_for(&self, target: &T) -> bool {
        self.armed.as_ref() == Some(target)
    }

    pub(super) fn request(&mut self, target: T) -> bool {
        if self.is_armed_for(&target) {
            self.armed = None;
            true
        } else {
            self.armed = Some(target);
            false
        }
    }

    pub(super) fn clear(&mut self) {
        self.armed = None;
    }
}

#[cfg(test)]
mod tests {
    use super::TargetConfirmation;

    #[test]
    fn confirmation_is_bound_to_the_exact_target_and_consumed_once() {
        let mut confirmation = TargetConfirmation::default();
        assert!(!confirmation.request("profile-a"));
        assert!(confirmation.is_armed_for(&"profile-a"));
        assert!(!confirmation.is_armed_for(&"profile-b"));
        assert!(!confirmation.request("profile-b"));
        assert!(!confirmation.is_armed_for(&"profile-a"));
        assert!(confirmation.request("profile-b"));
        assert!(!confirmation.is_armed_for(&"profile-b"));
    }
}
