use rbus_core::{RBusLibrary, RBusOpenError, RBusProperty, RBusValue};

// Requires librbus, but no broker.
#[test]
fn property_view_preserves_owner_and_returns_retained_values() -> anyhow::Result<()> {
    let _library = match RBusLibrary::load() {
        Ok(library) => library,
        Err(RBusOpenError::NotAvailable) => {
            eprintln!("library is not available, test ignored");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let property = RBusProperty::new(c"borrowed", &RBusValue::from(&1_i32)?)?;
    let value = {
        let borrowed: &rbus_core::RBusPropertyRef = &property;
        assert_eq!(borrowed.get::<i32>()?, 1);
        borrowed.set_name(c"updated");
        borrowed.set(&42_i32);
        borrowed.get_value()
    };

    assert_eq!(property.get_name(), c"updated");
    assert_eq!(property.get::<i32>()?, 42);
    drop(property);
    assert_eq!(value.get::<i32>()?, 42);
    Ok(())
}
