use rbus_core::{RBusEventHandler, RBusEventRef, RBusHandle, RBusLibrary};
use std::ffi::CString;

struct EventHandler;

impl RBusEventHandler for EventHandler {
    fn on_event(event_data: &RBusEventRef<'_>) {
        println!(
            "{:p}: {:?}: {:?}",
            event_data.handle().to_raw(),
            event_data.name(),
            event_data.kind()
        );
        let _ = event_data.with_data(|data| {
            for property in data.get_properties().iter() {
                println!("  {:?} = {:?}", property.get_name(), property.get_value());
            }
        });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event_name = std::env::args()
        .nth(1)
        .ok_or("usage: cargo run -p rbus-core --example subscribe_event -- EVENT_NAME")?;
    let event_name = CString::new(event_name)?;
    let library = RBusLibrary::load()?;
    let bus = RBusHandle::open(&library, c"rbus-event-listener")?;
    let subscription = bus.subscribe_event::<EventHandler>(&event_name)?;

    println!("Subscribed. Press Enter to unsubscribe and exit.");
    std::io::stdin().read_line(&mut String::new())?;
    drop(subscription);
    Ok(())
}
