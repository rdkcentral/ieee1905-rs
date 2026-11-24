mod subscription;

pub use subscription::{RBusEventSubscription, RBusSubscribeOptions};

pub(crate) use subscription::dispatch_event;

use crate::{RBusHandleRef, RBusObjectRef};
use rbus_sys::{rbusEvent_t, rbusEventType_t};
use std::ffi::CStr;
use std::os::raw::c_uint;

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
        // SAFETY: RBus keeps the payload valid for the native callback.
        let data = unsafe { RBusObjectRef::try_from_raw(self.event.data) }.ok()?;
        Some(f(&data))
    }
}
