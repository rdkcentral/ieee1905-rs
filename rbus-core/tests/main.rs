use rbus_core::*;
use std::ffi::CStr;
use std::sync::atomic::{AtomicI32, Ordering};

const ROOT_NAME: &CStr = c"Device.Test";
const TEST_VALUE: &CStr = c"Device.Test.Id";

struct TestProperty;

static PROPERTY_VALUE: AtomicI32 = AtomicI32::new(42);

impl RBusDataElementGet for TestProperty {
    fn get(_handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError> {
        let raw = PROPERTY_VALUE.load(Ordering::Relaxed);
        println!("get_handler: {raw}");

        property.set(&raw);
        Ok(())
    }
}

impl RBusDataElementSet for TestProperty {
    fn set(_handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError> {
        let value = property.get::<i32>().unwrap();

        PROPERTY_VALUE.store(value, Ordering::Relaxed);
        println!("set_handler: {value}");

        Ok(())
    }
}

#[test]
fn test_properties() -> anyhow::Result<()> {
    let status = RBusHandle::check_status();
    if status != RBusStatus::Enabled {
        anyhow::bail!("RBus is not enabled: {status:?}");
    }

    let bus = RBusHandle::open(ROOT_NAME)?;
    let property = RBusDataElement::property_rw::<TestProperty>(TEST_VALUE);

    bus.register_data_elements(&[property])?;

    set_al_mac(&bus, 1)?;
    assert_eq!(get_al_mac(&bus)?, 1);

    set_al_mac(&bus, 2)?;
    assert_eq!(get_al_mac(&bus)?, 2);

    set_al_mac(&bus, 3)?;
    assert_eq!(get_al_mac(&bus)?, 3);

    Ok(())
}

fn get_al_mac(bus: &RBusHandle) -> anyhow::Result<i32> {
    let value = bus.get(TEST_VALUE)?;
    println!("get: value = {value}");
    Ok(value)
}

fn set_al_mac(bus: &RBusHandle, raw: i32) -> anyhow::Result<()> {
    bus.set(TEST_VALUE, &raw)?;
    println!("set: value = {raw}");
    Ok(())
}
