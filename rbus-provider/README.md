# RBus Provider

The goal of this crate is to provide a simple way to implement interface for RBus providers.

So instead of registering each element by hand and setting/handling callbacks, it can be written with a simple DSL-like structure:
```rust
fn register_provider() -> RBusProvider {
    RBusProvider::open("RBusDevice", || (
      rbus_property("ID", DeviceHandler),
      rbus_property("Name", DeviceHandler),
      rbus_object("BuildInfo", (
        rbus_property("Version", DeviceInfoHandler),
        rbus_property("Architecture", DeviceInfoHandler),
      )),
      rbus_table("Interfaces", DeviceInterfacesHandler, (
        rbus_property("Mac", /* ... */),
        rbus_property("Type", /* ... */),
      ))
    ))
}
```

# Main Components

RBus Provider crate tries to be minimalistic and has only two main components:
- `RBusProvider` - entry point component that initializes RBus handle and registers all tables/objects/properties
- `RBusProviderElement` - trait representing an accessible via RBus entity (tuple/tables/objects/properties)

# Elements

## Object Element

This element represents a single object that can have other nested elements accessible via `name`.

It is created via `rbus_object` helper:

```rust
fn build_device_element() -> impl RBusProviderElement {
  rbus_object("BuildInfo", (
    rbus_property("Version", DeviceInfoHandler),
    rbus_property("Architecture", DeviceInfoHandler),
    rbus_object("Vendor", /* ... */),
    rbus_table("SupportedExtensions", /* ... */),
  ))
}
```

## Table Element

This element represents a multiple object that can have other nested elements accessible via `index+name` pair.

It is created via `rbus_table` helper:

```rust
fn build_device_interfaces_element() -> impl RBusProviderElement {
    rbus_table("Interfaces", DeviceInterfacesHandler, (
        // other child elements go here
        rbus_property("Mac", /* ... */),
        rbus_property("Type", /* ... */),
        rbus_object("Info", /* ... */),
        rbus_table("ConnectedNodes", /* ... */),
    ))
}
```

Each table requires a handler that provides a number of rows in the table:

```rust
struct DeviceInterfacesHandler;

impl RBusProviderTableSync for DeviceInterfacesHandler {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        Ok(42) // this table has 42 rows
    }
}
```

## Property Element

This element represents a property that can be read from or written to.

It is created via `rbus_property` helper:

```rust
fn build_name_element() -> impl RBusProviderElement {
    rbus_property("Name", DeviceNameHandler)
}
```

Each property requires a handler that allows to read value it represents:

```rust
struct DeviceNameHandler;

impl RBusProviderGetter for DeviceNameHandler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        args.property.set("router-9000");
        Ok(())
    }
}
```

## Tuple Element

This element represents a collection of elements that might have a different type.

Tuples don't require any builder methods and instead are just plain Rust tuples of elements:

```rust
fn build_device_interface_elements() -> impl RBusProviderElement {
    (
        rbus_property("Mac", /* ... */),
        rbus_property("Type", /* ... */),
        rbus_object("Info", /* ... */),
        rbus_table("ConnectedNodes", /* ... */),
    )
}
```

Due to current Rust limitations (namely absence of the variadic generics),
tuples have a limited number of items they can hold.
Tuples can be nested in case this limit was reached:

```rust
// this tuple is identical to the one in the previous example but can store more elements
fn build_device_interface_elements() -> impl RBusProviderElement {
    (
        (
            rbus_property("Mac", /* ... */),
            rbus_property("Type", /* ... */),
        ),
        (
            rbus_object("Info", /* ... */),
            rbus_table("ConnectedNodes", /* ... */),
        ),
    );
}
```

## Element Handlers

Most elements require handlers to provide access to the data they represent.

Different elements can share the same handler.
Arguments can be used to distinguish which element the handler was called for:
```rust
fn build_device_elements() -> impl RBusProviderElement {
    (
        rbus_property("ID", DeviceHandler),
        rbus_property("Name", DeviceHandler),
    )
}

struct DeviceHandler;

impl RBusProviderGetter for DeviceHandler {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        match args.path_name.as_bytes() {
            b"ID" => {
                args.property.set("1234-5678-4321-8765");
            }
            b"Name" => {
                args.property.set("router-9000");
            }
            _ => return Err(RBusError::ElementDoesNotExists),
        }
        Ok(())
    }
}
```

Arguments provide full information about the property being accessed:
- `RBusProperty` handle
- property path name (for ex. `Mac`)
- property full path (for ex. `Device.Interfaces.0.Mac`)
- all preceding table indices (for ex. `[0]` in case of `Device.Interfaces.0.Mac`)
- custom user data, that can be attached to a specific property instance

  **NOTE:** this data is attached to a specific path (instance of the value) being accessed, not the property itself
  - for example. `Device.Interfaces.0.Mac` and `Device.Interfaces.1.Mac`
    - handler is the same for both paths
    - user data will be different for both paths
    - this might be helpful when working with nested tables or when handling different properties with the same handler
