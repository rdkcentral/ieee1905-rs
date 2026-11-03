use anyhow::{Context, ensure};
use rbus_core::{RBusDataElement, RBusHandle, RBusLibrary, RBusStatus};
use std::ffi::CString;

// Requires librbus and a running broker; use Valgrind to detect invalid reads.
#[test]
fn collected_row_names_survive_iterator_drop() -> anyhow::Result<()> {
    let library = RBusLibrary::load().context("load librbus and its native dependencies")?;
    ensure!(
        library.check_status() == RBusStatus::Enabled,
        "RBus must be enabled and its broker running"
    );

    let component = CString::new(format!("Device.RowNameOwnershipTest{}", std::process::id()))?;
    let table = CString::new(format!("{}.Rows.", component.to_str()?))?;
    let element = CString::new(format!("{}{{i}}", table.to_str()?))?;
    let expected_name = format!("{}1", table.to_str()?);
    let expected_alias = c"ownership-test-row";

    let bus = RBusHandle::open(&library, &component).context("open test component")?;
    bus.register_data_elements(&[RBusDataElement::table(&element)])
        .context("register test table")?;
    bus.register_table_row(&table, 1, Some(expected_alias))
        .context("register test row with an alias")?;

    let names = bus
        .get_table_row_names(&table)
        .context("get test table rows")?;
    let rows: Vec<_> = names.iter().collect();

    // The iterator is dropped; names still owns the list.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].instance, 1);
    let name = rows[0].name.to_bytes();
    // Accept either convention for a trailing separator in a table row name.
    assert_eq!(
        name.strip_suffix(b".").unwrap_or(name),
        expected_name.as_bytes()
    );
    let alias = rows[0].alias.as_ref().expect("registered alias is missing");
    assert_eq!(alias.to_bytes(), expected_alias.to_bytes());

    drop(rows);
    assert_eq!(names.iter().count(), 1);
    drop(names);
    drop(bus);
    Ok(())
}
