use rbus_sys::*;
use std::os::raw::c_uint;

///
/// The type of events which can be subscribed to or published
///
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum RBusStatus {
    /// RBus broker is Enabled and Running
    Enabled,
    /// RBus broker will be Enabled on Reboot
    EnablePending,
    /// RBus broker will be Disabled on Reboot
    DisablePending,
    /// RBus broker is disabled
    Disabled,
    /// RBus status is unknown
    Unexpected(c_uint),
}

impl RBusStatus {
    pub fn map_err<F, E>(self, f: impl FnOnce(Self) -> E) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        if self == Self::Enabled {
            Ok(())
        } else {
            Err(f(self))
        }
    }

    pub(crate) fn from_raw(value: rbusStatus_t) -> Self {
        match value {
            rbusStatus_t::RBUS_ENABLED => Self::Enabled,
            rbusStatus_t::RBUS_ENABLE_PENDING => Self::EnablePending,
            rbusStatus_t::RBUS_DISABLE_PENDING => Self::DisablePending,
            rbusStatus_t::RBUS_DISABLED => Self::Disabled,
            e => Self::Unexpected(e.0),
        }
    }
}
