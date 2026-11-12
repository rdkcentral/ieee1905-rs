use rbus_core::{RBusLibrary, RBusOpenError};
use std::thread;

// Requires librbus, but no broker.
#[test]
fn concurrent_loads_share_the_same_library() -> anyhow::Result<()> {
    let first = thread::spawn(RBusLibrary::load);
    let second = thread::spawn(RBusLibrary::load);
    let first = first.join().expect("loading thread panicked");
    let second = second.join().expect("loading thread panicked");

    match (first, second) {
        (Ok(first), Ok(second)) => assert!(std::ptr::eq(first, second)),
        (Err(RBusOpenError::NotAvailable), Err(RBusOpenError::NotAvailable)) => {
            eprintln!("library is not available, test ignored");
        }
        (Err(error), _) | (_, Err(error)) => return Err(error.into()),
    }
    Ok(())
}
