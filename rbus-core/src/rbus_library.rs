use crate::{RBusError, RBusStatus};
use rbus_sys::{RBusLibraryRaw, rbusLogLevel_t};
use std::collections::HashSet;
use std::ffi::{CStr, c_uint};
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use thiserror::Error;

#[derive(Clone)]
#[repr(transparent)]
pub struct RBusLibrary {
    inner: Arc<RBusLibraryInner>,
}

struct RBusLibraryInner {
    handle: RBusLibraryRaw,
    reserved_component_names: Mutex<HashSet<Arc<CStr>>>,
}

pub(crate) struct RBusComponentNameReservation {
    library: RBusLibrary,
    component_name: Arc<CStr>,
}

impl Drop for RBusComponentNameReservation {
    fn drop(&mut self) {
        self.library
            .reserved_component_names()
            .remove(self.component_name.as_ref());
    }
}

impl RBusLibrary {
    /// Access RBus using the selected link mode (runtime loading by default).
    pub fn load() -> Result<Self, RBusOpenError> {
        static CELL: OnceLock<Result<RBusLibrary, RBusOpenError>> = OnceLock::new();
        let library = CELL.get_or_init(|| {
            let handle = unsafe { RBusLibraryRaw::load() }.map_err(|error| match error {
                rbus_sys::libloading::Error::DlOpen { .. }
                | rbus_sys::libloading::Error::DlOpenUnknown => RBusOpenError::NotAvailable,
                error => RBusOpenError::LoadFailed(Arc::from(error.to_string())),
            })?;
            Ok(RBusLibrary {
                inner: Arc::new(RBusLibraryInner {
                    handle,
                    reserved_component_names: Mutex::new(HashSet::new()),
                }),
            })
        });
        library.clone()
    }

    ///
    /// Components use this API to check whether the rbus-provider is enabled in this device/platform
    ///
    /// Used by: Components that uses rbus-provider to register events, tables and parameters.
    ///
    pub fn check_status(&self) -> RBusStatus {
        let raw = unsafe { self.as_raw().rbus_checkStatus() };
        RBusStatus::from_raw(raw)
    }

    ///
    /// A callback handler to get the log messages to the application context
    ///
    /// Used by: Component that wants to handle the logs in its own way
    /// must register a callback handler to get the log messages.
    ///
    pub fn register_log_handler<T>(&self) -> Result<(), RBusError>
    where
        T: RBusLogHandler,
    {
        unsafe extern "C" fn log<T: RBusLogHandler>(
            level: rbusLogLevel_t,
            file: *const c_char,
            line: c_int,
            thread_id: c_int,
            message: *mut c_char,
        ) {
            let file = if file.is_null() {
                c""
            } else {
                unsafe { CStr::from_ptr(file) }
            };

            let message = if message.is_null() {
                c""
            } else {
                unsafe { CStr::from_ptr(message) }
            };

            T::print_log(RBusLogRecord {
                level: level.into(),
                thread_id: thread_id.cast_unsigned(),
                file,
                line: line.cast_unsigned(),
                message,
            });
        }

        let result = unsafe { self.as_raw().rbus_registerLogHandler(Some(log::<T>)) };
        RBusError::map(result, || ())
    }

    pub(crate) fn as_raw(&self) -> &RBusLibraryRaw {
        &self.inner.handle
    }

    pub(crate) fn reserve_component_name(
        &self,
        component_name: &CStr,
    ) -> Result<RBusComponentNameReservation, RBusError> {
        let mut component_names = self.reserved_component_names();
        if component_names.contains(component_name) {
            return Err(RBusError::ComponentNameDuplication);
        }

        let component_name = Arc::<CStr>::from(component_name);
        component_names.insert(component_name.clone());
        Ok(RBusComponentNameReservation {
            library: self.clone(),
            component_name,
        })
    }

    fn reserved_component_names(&self) -> MutexGuard<'_, HashSet<Arc<CStr>>> {
        self.inner
            .reserved_component_names
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[derive(Debug, Error, Clone)]
pub enum RBusOpenError {
    #[error("Library not available")]
    NotAvailable,
    #[error("Load library failed: {0}")]
    LoadFailed(Arc<str>),
}

///
/// A callback handler to get the log messages to the application context
///
/// A component that wants to handle the logs in its own way must register a callback
/// handler to get the log messages.
///
pub trait RBusLogHandler {
    fn print_log(record: RBusLogRecord);
}

#[derive(Debug)]
pub struct RBusLogRecord<'a> {
    /// log level
    pub level: RBusLogLevel,
    /// file name that it prints
    pub file: &'a CStr,
    /// line number in the file
    pub line: u32,
    /// threadId
    pub thread_id: u32,
    /// log message the library prints
    pub message: &'a CStr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RBusLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Unknown(c_uint),
}

impl From<rbusLogLevel_t> for RBusLogLevel {
    fn from(value: rbusLogLevel_t) -> Self {
        match value {
            rbusLogLevel_t::RBUS_LOG_DEBUG => Self::Debug,
            rbusLogLevel_t::RBUS_LOG_INFO => Self::Info,
            rbusLogLevel_t::RBUS_LOG_WARN => Self::Warn,
            rbusLogLevel_t::RBUS_LOG_ERROR => Self::Error,
            rbusLogLevel_t::RBUS_LOG_FATAL => Self::Fatal,
            _ => Self::Unknown(value.0),
        }
    }
}
