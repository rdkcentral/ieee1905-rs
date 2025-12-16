use parking_lot::Mutex;
use rbus_core::RBusError;
use rbus_provider::element::RBusProviderElement;
use rbus_provider::element::object::rbus_object;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs, rbus_property};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs, rbus_table};
use rbus_provider::provider::RBusProvider;
use std::sync::Arc;

#[derive(Default)]
struct TestState {
    values: Vec<(String, Vec<String>)>,
}

///
///
///
struct Table1Handler(Arc<Mutex<TestState>>);

impl RBusProviderTableSync for Table1Handler {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        Ok(self.0.lock().values.len() as u32)
    }
}

///
///
///
struct Table2Handler(Arc<Mutex<TestState>>);

impl RBusProviderTableSync for Table2Handler {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let closure = || {
            let lock = self.0.lock();
            let index = args.table_idx.get(0).copied()?;
            let table = &lock.values.get(index as usize)?.1;
            Some(table.len() as u32)
        };
        closure().ok_or(RBusError::ElementDoesNotExists)
    }
}

///
///
///
struct Value1Handler(Arc<Mutex<TestState>>);

impl RBusProviderGetter for Value1Handler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let closure = || {
            let lock = self.0.lock();
            let index = args.table_idx.get(0).copied()?;
            let value = &lock.values.get(index as usize)?.0;
            args.property.set(value);
            Some(())
        };
        closure().ok_or(RBusError::ElementDoesNotExists)
    }
}

///
///
///
struct Value2Handler(Arc<Mutex<TestState>>);

impl RBusProviderGetter for Value2Handler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let closure = || {
            let lock = self.0.lock();
            let index1 = args.table_idx.get(0).copied()?;
            let index2 = args.table_idx.get(1).copied()?;
            let table = &lock.values.get(index1 as usize)?.1;
            let value = table.get(index2 as usize)?;
            args.property.set(value);
            Some(())
        };
        closure().ok_or(RBusError::ElementDoesNotExists)
    }
}

#[test]
fn main() -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(TestState::default()));
    let provider = RBusProvider::open(c"Test.Nest", || build_dsl(state.clone()))?;

    let handle = provider.handle();
    assert!(handle.get_value(c"Test.Nest.T.0.V").is_err());
    assert!(handle.get_value(c"Test.Nest.T.0.T.0.V").is_err());

    state.lock().values = vec![(
        "v1".to_string(),
        vec!["v1_1".to_string(), "v1_2".to_string()],
    )];
    assert_eq!(handle.get(c"Test.Nest.T.0.V"), Ok("v1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.0.T.0.V"), Ok("v1_1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.0.T.1.V"), Ok("v1_2".to_string()));
    assert!(handle.get_table_row_names(c"Test.Nest.T.0.T.2.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.1.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.1.T.0.V").is_err());

    state.lock().values = vec![
        ("v1".to_string(), vec![]),
        (
            "v2".to_string(),
            vec!["v2_1".to_string(), "v2_2".to_string()],
        ),
    ];
    assert_eq!(handle.get(c"Test.Nest.T.0.V"), Ok("v1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.1.V"), Ok("v2".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.1.T.0.V"), Ok("v2_1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.1.T.1.V"), Ok("v2_2".to_string()));
    assert!(handle.get_table_row_names(c"Test.Nest.T.0.T.0.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.1.T.2.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.2.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.2.T.0.V").is_err());

    state.lock().values = vec![
        ("v1".to_string(), vec!["v1_1".to_string()]),
        ("v2".to_string(), vec!["v2_1".to_string()]),
    ];
    assert_eq!(handle.get(c"Test.Nest.T.0.V"), Ok("v1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.0.T.0.V"), Ok("v1_1".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.1.V"), Ok("v2".to_string()));
    assert_eq!(handle.get(c"Test.Nest.T.1.T.0.V"), Ok("v2_1".to_string()));
    assert!(handle.get_table_row_names(c"Test.Nest.T.0.T.1.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.1.T.1.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.2.V").is_err());
    assert!(handle.get_table_row_names(c"Test.Nest.T.2.T.0.V").is_err());

    Ok(())
}

#[rustfmt::skip]
fn build_dsl(state: Arc<Mutex<TestState>>) -> impl RBusProviderElement {
    (
        rbus_object("Test", (
            rbus_object("Nest", (
                rbus_table("T", Table1Handler(state.clone()), (
                    rbus_table("T", Table2Handler(state.clone()), (
                        rbus_property("V", Value2Handler(state.clone())),
                    )),
                    rbus_property("V", Value1Handler(state.clone())),
                )),
            )),
        )),
    )
}
