#![allow(warnings)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub use libloading;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl RBusLibraryRaw {
    /// Access the linked library, or load `librbus.so.0` / `librbus.so` at runtime.
    ///
    /// # Safety
    /// The library must match the ABI of the headers used to generate the bindings.
    /// Loading a shared library may also execute its initialization routines.
    pub unsafe fn load() -> Result<Self, libloading::Error> {
        #[cfg(feature = "linked")]
        {
            Ok(Self)
        }
        #[cfg(not(feature = "linked"))]
        {
            match unsafe { Self::new("librbus.so.0") } {
                Err(libloading::Error::DlOpen { .. } | libloading::Error::DlOpenUnknown) => unsafe {
                    Self::new("librbus.so")
                },
                result => result,
            }
        }
    }
}
