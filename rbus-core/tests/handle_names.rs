use rbus_core::{
    RBusDataElement, RBusDataElementGet, RBusError, RBusHandle, RBusLibrary, RBusOpenError,
    RBusProperty,
};
use std::ffi::CString;
use std::sync::Barrier;
use std::thread;

// These tests require librbus and a running broker.
fn load_library() -> anyhow::Result<Option<RBusLibrary>> {
    match RBusLibrary::load() {
        Ok(library) => Ok(Some(library)),
        Err(RBusOpenError::NotAvailable) => {
            eprintln!("library is not available, test ignored");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

struct TestProperty;

impl RBusDataElementGet for TestProperty {
    fn get(_handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError> {
        property.set(&42_i32);
        Ok(())
    }
}

#[test]
fn duplicate_component_is_rejected_and_name_can_be_reused() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let name = CString::new(format!("Device.HandleNameTest{}", std::process::id()))?;
    let property = CString::new(format!("{}.Value", name.to_str()?))?;
    let element = RBusDataElement::property_ro::<TestProperty>(&property);

    let first = RBusHandle::open(&library, &name)?;
    first.register_data_elements(&[element])?;
    assert_eq!(first.get::<i32>(&property)?, 42);
    assert!(matches!(
        RBusHandle::open(&library, &name),
        Err(RBusError::ComponentNameDuplication)
    ));
    assert_eq!(first.get::<i32>(&property)?, 42);
    drop(first);

    let reopened = RBusHandle::open(&library, &name)?;
    reopened.register_data_elements(&[RBusDataElement::property_ro::<TestProperty>(&property)])?;
    assert_eq!(reopened.get::<i32>(&property)?, 42);
    Ok(())
}

#[test]
fn concurrent_opens_of_same_component_have_one_owner() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let name = CString::new(format!("Device.ConcurrentHandleTest{}", std::process::id()))?;
    let barrier = Barrier::new(2);
    let attempts = thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    RBusHandle::open(&library, &name)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("opening thread panicked"))
            .collect::<Vec<_>>()
    });

    assert_eq!(attempts.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|result| matches!(result, Err(RBusError::ComponentNameDuplication)))
            .count(),
        1
    );
    let bus = attempts.into_iter().find_map(Result::ok).unwrap();
    let property = CString::new(format!("{}.Value", name.to_str()?))?;
    bus.register_data_elements(&[RBusDataElement::property_ro::<TestProperty>(&property)])?;
    assert_eq!(bus.get::<i32>(&property)?, 42);
    Ok(())
}
