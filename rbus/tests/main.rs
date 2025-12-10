use rbus::*;
use std::ffi::CStr;
use std::sync::atomic::{AtomicI32, Ordering};

const ROOT_NAME: &CStr = c"Device.IEEE1905";
const AL_MAC_VALUE: &CStr = c"Device.IEEE1905.AL.1024.IEEE1905Id";

struct AlMacProperty;

static AL_MAC_PROPERTY_VALUE: AtomicI32 = AtomicI32::new(42);

impl RBusDataElementGet for AlMacProperty {
    fn get(property: &RBusProperty) -> Result<(), RBusError> {
        let raw = AL_MAC_PROPERTY_VALUE.load(Ordering::Relaxed);
        println!("get_handler: {raw}");

        property.set(&raw);
        Ok(())
    }
}

impl RBusDataElementSet for AlMacProperty {
    fn set(property: &RBusProperty) -> Result<(), RBusError> {
        let value = property.get::<i32>().unwrap();

        AL_MAC_PROPERTY_VALUE.store(value, Ordering::Relaxed);
        println!("set_handler: {value}");

        Ok(())
    }
}

#[test]
fn main() -> anyhow::Result<()> {
    let status = RBus::check_status();
    if status != RBusStatus::Enabled {
        anyhow::bail!("RBus is not enabled: {status:?}");
    }

    let bus = RBus::open(ROOT_NAME)?;
    let property = RBusDataElement::property_rw::<AlMacProperty>(AL_MAC_VALUE);

    bus.register_data_elements(&[property])?;

    set_al_mac(&bus, 1)?;
    assert_eq!(get_al_mac(&bus)?, 1);

    set_al_mac(&bus, 2)?;
    assert_eq!(get_al_mac(&bus)?, 2);

    set_al_mac(&bus, 3)?;
    assert_eq!(get_al_mac(&bus)?, 3);

    Ok(())
}

fn get_al_mac(bus: &RBus) -> anyhow::Result<i32> {
    let value = bus.get(AL_MAC_VALUE)?;
    println!("get_al_mac: value = {value}");
    Ok(value)
}

fn set_al_mac(bus: &RBus, raw: i32) -> anyhow::Result<()> {
    bus.set(AL_MAC_VALUE, &raw)?;
    println!("set_al_mac: value = {raw}");
    Ok(())
}
