use crate::RBusStatus;
use rbus_sys::RBusLibraryRaw;
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
