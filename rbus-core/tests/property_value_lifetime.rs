use rbus_core::{RBusLibrary, RBusOpenError, RBusProperty, RBusValue, RBusValueReadable};
use rbus_sys::rbusValueError_t;
use std::cell::RefCell;

thread_local! {
    static PROPERTY_TO_REPLACE: RefCell<Option<RBusProperty>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct ReplaceDuringRead(i32);

impl RBusValueReadable for ReplaceDuringRead {
    fn get(this: &mut Self, value: &RBusValue) -> rbusValueError_t {
        PROPERTY_TO_REPLACE.with(|slot| {
            let property = slot.borrow_mut().take().expect("property alias is missing");
            property.set(&2_i32);
        });

        // The original value must remain alive after the property releases it.
        <i32 as RBusValueReadable>::get(&mut this.0, value)
    }
}

// Requires librbus, but no broker; use Valgrind to detect invalid reads and leaks.
#[test]
fn property_value_survives_replacement_during_conversion() -> anyhow::Result<()> {
    let library = match RBusLibrary::load() {
        Ok(library) => library,
        Err(RBusOpenError::NotAvailable) => {
            eprintln!("library is not available, test ignored");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    // Dropping the temporary leaves the property as the value's only owner.
    let property = RBusProperty::new(
        &library,
        c"test.value-lifetime",
        &RBusValue::from(&library, &1_i32),
    );
    PROPERTY_TO_REPLACE.with(|slot| {
        *slot.borrow_mut() = Some(property.clone());
    });

    let previous = property.get::<ReplaceDuringRead>()?;
    assert_eq!(previous.0, 1);
    assert_eq!(property.get::<i32>()?, 2);
    Ok(())
}
