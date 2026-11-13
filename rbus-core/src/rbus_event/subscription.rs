use super::{RBusEventHandler, RBusEventRef};
use crate::{RBusHandle, RBusHandleRef};
use rbus_sys::{rbusEvent_t, rbusEventSubscription_t, rbusHandle_t};
use std::ffi::CString;
use std::panic::catch_unwind;
use std::time::Duration;

/// Options for establishing a subscription.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RBusSubscribeOptions {
    /// Time to retry when no provider is available, rounded up to whole seconds.
    /// Zero disables retries. This does not limit the subscription's lifetime.
    pub timeout: Duration,
}

///
/// A subscription borrowing its owning connection.
/// Dropping this guard requests unsubscription. Native RBus may still deliver
/// a late callback after unsubscription.
///
/// ```compile_fail,E0597
/// use rbus_core::{RBusEvent, RBusEventHandler, RBusEventRef, RBusHandle, RBusLibrary};
/// struct Handler;
/// impl RBusEventHandler for Handler {
///     fn on_event(_: &RBusEventRef<'_>) {}
/// }
/// fn example(library: &RBusLibrary) -> Result<(), Box<dyn std::error::Error>> {
///     let subscription = {
///         let bus = RBusHandle::open(library, c"subscriber")?;
///         RBusEvent::subscribe::<Handler>(&bus, c"Device.Test.Event!")?
///     };
///     drop(subscription);
///     Ok(())
/// }
/// ```
#[must_use = "keep the subscription alive to receive events"]
pub struct RBusEventSubscription<'a> {
    pub(super) handle: &'a RBusHandle,
    pub(super) event_name: CString,
}

pub(super) unsafe extern "C" fn dispatch_event<T: RBusEventHandler>(
    handle: rbusHandle_t,
    event_data: *const rbusEvent_t,
    _subscription: *mut rbusEventSubscription_t,
) {
    // Catch unwinding panics before returning to C. Aborting panics terminate the process.
    if let Err(payload) = catch_unwind(|| {
        if handle.is_null() {
            return;
        }
        // SAFETY: RBus owns the event for the duration of this callback.
        let Some(event_data) = (unsafe { event_data.as_ref() }) else {
            return;
        };
        if event_data.name.is_null() {
            return;
        }
        // SAFETY: RBus keeps the connection and payload valid until this callback returns.
        let _ = unsafe {
            RBusHandleRef::run_with_raw(handle, |handle| {
                T::on_event(&RBusEventRef {
                    handle,
                    event: event_data,
                });
                Ok(())
            })
        };
    }) {
        // Dropping the panic payload could panic across the FFI boundary.
        std::mem::forget(payload);
    }
}

impl Drop for RBusEventSubscription<'_> {
    fn drop(&mut self) {
        unsafe {
            self.handle
                .library()
                .as_raw()
                .rbusEvent_Unsubscribe(self.handle.handle, self.event_name.as_ptr())
        };
    }
}
