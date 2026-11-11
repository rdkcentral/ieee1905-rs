use rbus_core::{RBusLibrary, RBusObject, RBusOpenError, RBusProperty, RBusValue};

fn load_library() -> anyhow::Result<Option<RBusLibrary>> {
    match RBusLibrary::load() {
        Ok(library) => Ok(Some(library)),
        Err(RBusOpenError::NotAvailable) => {
            eprintln!("librbus is not available; skipping name ownership test");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

// Requires librbus, but no running broker. Run under Valgrind to detect UAFs.
#[test]
fn object_name_survives_renaming_and_drop() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };

    for original in [c"Device.Original", c"", c"Device.\xff"] {
        let object = RBusObject::new(&library, original);
        let alias = object.clone();
        let name = object.get_name();

        object.set_name(c"Device.Renamed");
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(object.get_name().to_bytes(), b"Device.Renamed");

        let renamed = object.get_name();
        alias.set_name(c"Device.RenamedViaClone");
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(renamed.to_bytes(), b"Device.Renamed");
        assert_eq!(object.get_name().to_bytes(), b"Device.RenamedViaClone");

        drop(object);
        drop(alias);
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(renamed.to_bytes(), b"Device.Renamed");
    }
    Ok(())
}

#[test]
fn property_name_survives_renaming_and_drop() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };

    let value = RBusValue::new(&library);
    for original in [c"Device.Original", c"", c"Device.\xff"] {
        let property = RBusProperty::new(&library, original, &value);
        let alias = property.clone();
        let name = property.get_name();

        property.set_name(c"Device.Renamed");
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(property.get_name().to_bytes(), b"Device.Renamed");

        let renamed = property.get_name();
        alias.set_name(c"Device.RenamedViaClone");
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(renamed.to_bytes(), b"Device.Renamed");
        assert_eq!(property.get_name().to_bytes(), b"Device.RenamedViaClone");

        drop(property);
        drop(alias);
        assert_eq!(name.to_bytes(), original.to_bytes());
        assert_eq!(renamed.to_bytes(), b"Device.Renamed");
    }
    Ok(())
}
