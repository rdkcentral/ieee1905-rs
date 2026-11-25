use rbus_core::RBusStatus;

#[test]
fn enabled_status_does_not_invoke_error_callback() {
    let result = RBusStatus::Enabled.map_err(|status| {
        panic!("error callback invoked for {status:?}");
    });

    assert_eq!(result, Ok::<(), RBusStatus>(()));
}

#[test]
fn other_statuses_accept_inferred_fn_once_callbacks() {
    for status in [
        RBusStatus::EnablePending,
        RBusStatus::DisablePending,
        RBusStatus::Disabled,
        RBusStatus::Unexpected(42),
    ] {
        let message = String::from("RBus unavailable");
        let result = status.map_err(|received| (received, message));

        assert_eq!(result, Err((status, String::from("RBus unavailable"))));
    }
}
