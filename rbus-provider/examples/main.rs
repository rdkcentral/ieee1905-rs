use rbus_core::RBusError;
use rbus_provider::element::object::rbus_object;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs, rbus_property};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs, rbus_table};
use rbus_provider::provider::{RBusProvider, RBusProviderError};

fn main() -> anyhow::Result<()> {
    println!("registering RBus provider");
    let provider = register_provider()?;

    println!("RBus provider registered");
    std::thread::sleep(std::time::Duration::from_mins(1));

    Ok(drop(provider))
}

#[rustfmt::skip]
fn register_provider() -> Result<RBusProvider, RBusProviderError> {
    RBusProvider::open(c"ExampleDevice", ||
        rbus_object("Device", (
            rbus_property("ID", DeviceHandler),
            rbus_property("Name", DeviceHandler),
            rbus_object("BuildInfo", (
                rbus_property("Version", DeviceHandler),
                rbus_property("Architecture", DeviceHandler),
            )),
            rbus_table("Interfaces", DeviceInterfacesHandler, (
                rbus_property("Mac", DeviceInterfacesHandler),
                rbus_property("Type", DeviceInterfacesHandler),
            )),
        ))
    )
}

///////////////////////////////////////////////////////////////////////////
// DeviceHandler
///////////////////////////////////////////////////////////////////////////
struct DeviceHandler;

impl RBusProviderGetter for DeviceHandler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        println!("DeviceHandler -> {}", args.path_full);

        match &**args.path_name {
            b"ID" => {
                args.property.set("1234-5678-8765-4321");
            }
            b"Name" => {
                args.property.set("router-9000");
            }
            b"Version" => {
                args.property.set("1.0.4");
            }
            b"Architecture" => {
                args.property.set("arm64-v8a");
            }
            _ => return Err(RBusError::ElementDoesNotExists),
        }
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////
// DeviceInterfacesHandler
///////////////////////////////////////////////////////////////////////////
struct DeviceInterfacesHandler;

impl RBusProviderTableSync for DeviceInterfacesHandler {
    type UserData = ();

    fn len(&mut self, _args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        Ok(2)
    }
}

impl RBusProviderGetter for DeviceInterfacesHandler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        println!("DeviceInterfacesHandler -> {}", args.path_full);

        let Some(index) = args.table_idx.get(0) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match &**args.path_name {
            b"Mac" => {
                args.property.set(&format!("00-00-00-00-00-{index:02}"));
            }
            b"Type" => {
                args.property.set(&format!("IEEE 802.11"));
            }
            _ => return Err(RBusError::ElementDoesNotExists),
        }
        Ok(())
    }
}
