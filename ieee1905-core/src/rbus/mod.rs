#![allow(non_camel_case_types)]

use crate::rbus::id::RBus_Ieee1905Id;
use crate::rbus::nt_device_id::RBus_NetworkTopology_Ieee1905Device_Ieee1905Id;
use anyhow::{anyhow, bail};
use rbus::{RBus, RBusDataElement, RBusError};
use std::ffi::CString;
use tracing::{debug, error, info, instrument, warn};

mod id;
mod nt_device_id;

macro_rules! c_format {
    ($($arg:tt)*) => {
        CString::new(format!($($arg)*))
    }
}

///
/// Connection to RBus component
///
pub struct RBusConnection {
    handle: RBus,
    table: RRubElementsTable,
}

impl RBusConnection {
    #[instrument(name = "rbus_open")]
    pub fn open() -> anyhow::Result<Self> {
        let handle = RBus::open(c"Device.IEEE1905")
            .map_err(|e| anyhow!("failed to open RBus connection: {e}"))?;

        for instance in 0..4 {
            debug!(instance, "registering RBus elements");

            let table = RRubElementsTable::new(instance)?;
            let result = handle.register_data_elements(table.elements().as_slice());
            match result {
                Ok(_) => {
                    info!(instance, "RBus elements successfully registered");
                    return Ok(Self { handle, table });
                }
                Err(RBusError::ElementNameDuplication) => {
                    warn!(instance, "RBus elements already registered");
                }
                Err(e) => bail!("failed to register RBus elements: {e}"),
            }
        }
        bail!("failed to register RBus elements, too many instances present");
    }
}

impl Drop for RBusConnection {
    fn drop(&mut self) {
        let elements = self.table.elements();
        if let Err(e) = self.handle.unregister_data_elements(&elements) {
            error!("failed to unregister RBus elements: {e:?}");
        }
    }
}

///
/// Table of RBus ieee1905 elements
///
/// Needed to support dynamic naming of elements because RBus doesn't allow different
/// processes to register the same table.
/// More info can be found [here](https://github.com/rdkcentral/ieee1905-rs/issues/139#issuecomment-3631485966).
///
/// Can be changed to a simple const/static array when this limitation will be lifted.
///
struct RRubElementsTable {
    id: CString,
    nt_device: CString,
    nt_device_id: CString,
}

#[rustfmt::skip]
impl RRubElementsTable {
    fn new(instance: u32) -> anyhow::Result<Self> {
        let base = format!("Device.IEEE1905.AL.{instance}");

        Ok(Self {
            // Device.IEEE1905.AL.{i}.IEEE1905Id
            id: c_format!("{base}.IEEE1905Id")?,
            // Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.
            nt_device: c_format!("{base}.NetworkTopology.IEEE1905Device.{{i}}.")?,
            // Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Id
            nt_device_id: c_format!("{base}.NetworkTopology.IEEE1905Device.{{i}}.IEEE1905Id")?,
        })
    }

    fn elements(&self) -> [RBusDataElement<'_>; 3] {
        [
            RBusDataElement::property_ro::<RBus_Ieee1905Id>(&self.id),
            RBusDataElement::table(&self.nt_device),
            RBusDataElement::property_ro::<RBus_NetworkTopology_Ieee1905Device_Ieee1905Id>(&self.nt_device_id),
        ]
    }
}
