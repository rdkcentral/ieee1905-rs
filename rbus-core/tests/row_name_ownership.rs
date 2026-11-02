use anyhow::{Context, ensure};
use rbus_core::{RBusDataElement, RBusHandle, RBusLibrary, RBusStatus};
use std::ffi::CString;

/// Collecting rows must leave their names and aliases readable after the
/// iterator frees the native list, even though the bus is still open.
///
/// Requires a loadable librbus and a running broker. Missing prerequisites are
/// errors, not skipped tests. Run under a memory checker: freed memory can still
/// contain the expected bytes, so passing assertions alone do not prove safety.
/// For example, on x86_64 Linux:
///
/// CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='valgrind --tool=memcheck --error-exitcode=99 --leak-check=no' cargo test -p rbus-core --test row_name_ownership -- --nocapture
#[test]
fn collected_row_names_survive_iterator_drop() -> anyhow::Result<()> {
    let library = RBusLibrary::load().context("load librbus and its native dependencies")?;
    ensure!(
        library.check_status() == RBusStatus::Enabled,
        "RBus must be enabled and its broker running"
    );

    // Isolate the namespace from other tests and concurrent test processes.
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

    let rows: Vec<_> = bus
        .get_table_row_names(&table)
        .context("get test table rows")?
        .collect();

    // collect() has consumed and dropped the iterator. No extra rbus operation
    // is needed to trigger the bug: these reads access the freed native strings
    // with the original binding. The same code also accepts owned CString fields.
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
    // Keep the bus alive through all string reads; closing it cleans up the
    // component's registrations, including when the test unwinds on failure.
    drop(bus);
    Ok(())
}
