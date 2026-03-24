use crate::{RBusError, RBusStatus};
use rbus_sys::{RBusLibraryRaw, rbusLogLevel_t};
use std::ffi::{CStr, c_uint};
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, OnceLock};
use thiserror::Error;

#[derive(Clone)]
#[repr(transparent)]
pub struct RBusLibrary {
    handle: Arc<RBusLibraryRaw>,
}

impl RBusLibrary {
    /// Dynamically load RBus library
    pub fn load() -> Result<Self, RBusOpenError> {
        static CELL: OnceLock<Result<RBusLibrary, RBusOpenError>> = OnceLock::new();
        let library = CELL.get_or_init(|| {
            for library_name in ["librbus.so.0", "librbus.so"] {
                match unsafe { RBusLibraryRaw::new(library_name) } {
                    Ok(e) => {
                        return Ok(RBusLibrary {
                            handle: Arc::new(e),
                        });
                    }
                    Err(rbus_sys::libloading::Error::DlOpen { .. }) => continue,
                    Err(rbus_sys::libloading::Error::DlOpenUnknown) => continue,
                    Err(e) => return Err(RBusOpenError::LoadFailed(Arc::from(e.to_string()))),
                }
            }
            Err(RBusOpenError::NotAvailable)
        });
        library.clone()
    }

    ///
    /// Components use this API to check whether the rbus-provider is enabled in this device/platform
    ///
    /// Used by: Components that uses rbus-provider to register events, tables and parameters.
    ///
    pub fn check_status(&self) -> RBusStatus {
        let raw = unsafe { self.handle.rbus_checkStatus() };
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

        let result = unsafe { self.handle.rbus_registerLogHandler(Some(log::<T>)) };
        RBusError::map(result, || ())
    }

    pub(crate) fn as_raw(&self) -> &RBusLibraryRaw {
        &self.handle
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
