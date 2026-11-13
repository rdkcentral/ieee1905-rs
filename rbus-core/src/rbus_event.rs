mod subscription;

pub use subscription::{RBusEventSubscription, RBusSubscribeOptions};

use subscription::dispatch_event;

use crate::{RBusError, RBusHandle, RBusHandleRef, RBusObjectRef};
use rbus_sys::{rbusEvent_t, rbusEventType_t};
use std::ffi::CStr;
use std::os::raw::c_uint;

///
/// Operations for subscribing to RBus events.
///
pub struct RBusEvent;

impl RBusEvent {
    ///
    /// Subscribe with no retry when no provider is available.
    /// See [`Self::subscribe_with_options`] for callback behavior.
    ///
    pub fn subscribe<'a, T: RBusEventHandler>(
        handle: &'a RBusHandle,
        event_name: &CStr,
    ) -> Result<RBusEventSubscription<'a>, RBusError> {
        Self::subscribe_with_options::<T>(handle, event_name, RBusSubscribeOptions::default())
    }

    ///
    /// Subscribe with options controlling retries during establishment.
    /// The callback runs on an RBus thread and may begin before this returns.
    /// With `panic = "unwind"`, callback panics are caught before returning to C.
    /// With `panic = "abort"`, including this workspace's release profile,
    /// a callback panic terminates the process.
    /// Create and drop subscriptions from outside event callbacks.
    /// Do not close the receiving connection from an event callback.
    ///
    pub fn subscribe_with_options<'a, T: RBusEventHandler>(
        handle: &'a RBusHandle,
        event_name: &CStr,
        options: RBusSubscribeOptions,
    ) -> Result<RBusEventSubscription<'a>, RBusError> {
        let mut timeout =
            i32::try_from(options.timeout.as_secs()).map_err(|_| RBusError::InvalidInput)?;

        // Round fractional seconds up to the next whole second.
        if options.timeout.subsec_nanos() != 0 {
            timeout = timeout.checked_add(1).ok_or(RBusError::InvalidInput)?;
        }

        // Native RBus multiplies the timeout by 1000 using a signed int.
        if timeout > i32::MAX / 1000 {
            return Err(RBusError::InvalidInput);
        }

        let event_name = event_name.to_owned();
        let result = unsafe {
            handle.library().as_raw().rbusEvent_Subscribe(
                handle.handle,
                event_name.as_ptr(),
                Some(dispatch_event::<T>),
                std::ptr::null_mut(),
                timeout,
            )
        };
        RBusError::map(result, || RBusEventSubscription { handle, event_name })
    }
}

/// Handles events on an RBus thread through a static method.
/// The same handler type may be used by multiple connections. Implementations
/// must synchronize access to any shared state they use.
pub trait RBusEventHandler {
    fn on_event(event: &RBusEventRef<'_>);
}

/// The type of a received RBus event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RBusEventType {
    ObjectCreated,
    ObjectDeleted,
    ValueChanged,
    General,
    InitialValue,
    Interval,
    DurationComplete,
    Unexpected(c_uint),
}

impl RBusEventType {
    fn from_raw(value: rbusEventType_t) -> Self {
        match value {
            rbusEventType_t::RBUS_EVENT_OBJECT_CREATED => Self::ObjectCreated,
            rbusEventType_t::RBUS_EVENT_OBJECT_DELETED => Self::ObjectDeleted,
            rbusEventType_t::RBUS_EVENT_VALUE_CHANGED => Self::ValueChanged,
            rbusEventType_t::RBUS_EVENT_GENERAL => Self::General,
            rbusEventType_t::RBUS_EVENT_INITIAL_VALUE => Self::InitialValue,
            rbusEventType_t::RBUS_EVENT_INTERVAL => Self::Interval,
            rbusEventType_t::RBUS_EVENT_DURATION_COMPLETE => Self::DurationComplete,
            other => Self::Unexpected(other.0),
        }
    }
}

///
/// An event borrowed for the duration of its callback.
/// The event, connection and payload are borrowed only for that callback.
///
/// ```compile_fail
/// use rbus_core::RBusEventRef;
/// fn keep(event: RBusEventRef<'_>) -> RBusEventRef<'static> { event }
/// ```
#[derive(Clone, Copy)]
pub struct RBusEventRef<'a> {
    handle: &'a RBusHandleRef,
    event: &'a rbusEvent_t,
}

impl<'a> RBusEventRef<'a> {
    ///
    /// Borrow the connection receiving this event.
    ///
    /// ```compile_fail
    /// use rbus_core::{RBusEventRef, RBusHandleRef};
    /// fn keep(event: RBusEventRef<'_>) -> &'static RBusHandleRef { event.handle() }
    /// ```
    pub fn handle(&self) -> &'a RBusHandleRef {
        self.handle
    }

    /// Get the fully qualified event name.
    pub fn name(&self) -> &'a CStr {
        // SAFETY: the callback validates the name and limits the event's lifetime.
        unsafe { CStr::from_ptr(self.event.name) }
    }

    /// Get the event type.
    pub fn kind(&self) -> RBusEventType {
        RBusEventType::from_raw(self.event.type_)
    }

    /// Call `f` with a temporary borrow of the event payload.
    /// Returns `None` without calling `f` if the event has no payload.
    ///
    /// ```compile_fail
    /// use rbus_core::{RBusEventRef, RBusObjectRef};
    /// fn keep(event: RBusEventRef<'_>) -> Option<&RBusObjectRef> {
    ///     event.with_data(|data| data)
    /// }
    /// ```
    pub fn with_data<T>(&self, f: impl FnOnce(&RBusObjectRef) -> T) -> Option<T> {
        let data = self.event.data;
        if data.is_null() {
            return None;
        }
        // SAFETY: RBus keeps the payload valid for the native callback.
        let data = unsafe { RBusObjectRef::from_raw(self.handle.library(), data) };
        Some(f(&data))
    }
}
