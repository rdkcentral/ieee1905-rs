use rbus_core::{RBusLibrary, RBusObject, RBusOpenError, RBusProperties, RBusProperty, RBusValue};

// These tests require librbus, but no broker. Run under Valgrind to check native lifetimes.
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

fn object_with_properties(library: &RBusLibrary) -> RBusObject {
    let object = RBusObject::new(library, c"test.properties");
    let first = RBusProperty::new(library, c"first", &RBusValue::from(library, &1_i32));
    first.append_property(&RBusProperty::new(
        library,
        c"second",
        &RBusValue::from(library, &2_i32),
    ));
    first.append_property(&RBusProperty::new(
        library,
        c"third",
        &RBusValue::from(library, &3_i32),
    ));
    object.set_properties(&first);
    object
}

fn assert_original_properties(properties: &RBusProperties) -> anyhow::Result<()> {
    assert!(!properties.is_empty());
    let mut iter = properties.iter();
    for (name, value) in [(c"first", 1_i32), (c"second", 2), (c"third", 3)] {
        let property = iter.next().expect("missing property");
        assert_eq!(property.get_name(), name);
        assert_eq!(property.get_value().get::<i32>()?, value);
    }
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
    Ok(())
}

#[test]
fn empty_object_returns_empty_collection() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = RBusObject::new(&library, c"test.empty");
    let properties = object.get_properties();
    drop(object);

    assert!(properties.is_empty());
    let mut iter = properties.iter();
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
    Ok(())
}

#[test]
fn properties_iterate_in_native_order_and_can_be_revisited() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = object_with_properties(&library);
    let properties = object.get_properties();

    assert_original_properties(&properties)?;
    assert_original_properties(&properties)?;
    Ok(())
}

#[test]
fn collection_survives_list_replacement_and_object_drop() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = object_with_properties(&library);
    let properties = object.get_properties();
    object.set_properties(&RBusProperty::new(
        &library,
        c"replacement",
        &RBusValue::from(&library, &4_i32),
    ));
    assert_eq!(
        object.get_properties().iter().next().unwrap().get_name(),
        c"replacement"
    );
    drop(object);

    assert_original_properties(&properties)
}

#[test]
fn returned_properties_survive_collection_and_iterator_drop() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = object_with_properties(&library);
    let properties: Vec<_> = object.get_properties().iter().collect();
    drop(object);

    assert_eq!(properties.len(), 3);
    for (index, property) in properties.iter().enumerate() {
        assert_eq!(property.get_value().get::<i32>()?, index as i32 + 1);
    }
    assert_eq!(properties[1].get_name(), c"second");
    Ok(())
}

#[test]
fn iterator_survives_collection_and_object_drop() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = object_with_properties(&library);
    let mut iter = object.get_properties().iter();
    drop(object);

    let first = iter.next().unwrap();
    assert_eq!(first.get_name(), c"first");
    drop(first);
    let second = iter.next().unwrap();
    drop(iter);
    assert_eq!(second.get_name(), c"second");
    assert_eq!(second.get_value().get::<i32>()?, 2);
    Ok(())
}

#[test]
fn iterator_retains_cursor_when_alias_replaces_next_property() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let object = object_with_properties(&library);
    let alias = object.clone();
    let properties = object.get_properties();
    let mut iter = properties.iter();
    let first = iter.next().unwrap();
    assert_eq!(first.get_name(), c"first");
    drop(first);

    // Unlink the iterator's cursor from the list through another object wrapper.
    alias.set_property(&RBusProperty::new(
        &library,
        c"second",
        &RBusValue::from(&library, &20_i32),
    ));
    assert_eq!(
        alias
            .get_property(c"second")
            .unwrap()
            .get_value()
            .get::<i32>()?,
        20
    );
    drop(alias);
    drop(object);
    drop(properties);

    let second = iter.next().unwrap();
    assert_eq!(second.get_name(), c"second");
    assert_eq!(second.get_value().get::<i32>()?, 2);
    drop(second);
    let third = iter.next().unwrap();
    drop(iter);
    assert_eq!(third.get_name(), c"third");
    assert_eq!(third.get_value().get::<i32>()?, 3);
    Ok(())
}
