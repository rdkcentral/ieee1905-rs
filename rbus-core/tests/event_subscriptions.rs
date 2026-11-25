use rbus_core::{
    RBusDataElement, RBusDataElementGet, RBusError, RBusEventHandler, RBusEventRef, RBusEventType,
    RBusHandle, RBusHandleRef, RBusLibrary, RBusOpenError, RBusPropertyRef, RBusSubscribeOptions,
};
use rbus_sys::*;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{OnceLock, mpsc};
use std::time::Duration;

// Requires librbus and a running broker. The fixture uses the native publication
// API so these tests do not require a new provider API in the Rust binding.
static NEXT_PROVIDER: AtomicUsize = AtomicUsize::new(1);
static PROPERTY_VALUE: AtomicI32 = AtomicI32::new(10);
const WAIT: Duration = Duration::from_secs(5);

struct PolledProperty;

impl RBusDataElementGet for PolledProperty {
    fn get(_handle: &RBusHandleRef, property: &RBusPropertyRef) -> Result<(), RBusError> {
        property.set(&PROPERTY_VALUE.load(Ordering::Relaxed));
        Ok(())
    }
}

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

unsafe extern "C" fn allow_subscription(
    _handle: rbusHandle_t,
    _action: rbusEventSubAction_t,
    name: *const std::ffi::c_char,
    _filter: rbusFilter_t,
    _interval: i32,
    auto_publish: *mut bool,
) -> rbusError_t {
    if !auto_publish.is_null() {
        unsafe { *auto_publish = false };
    }
    if unsafe { CStr::from_ptr(name) }
        .to_bytes()
        .ends_with(b"Denied!")
    {
        rbusError_t::RBUS_ERROR_ACCESS_NOT_ALLOWED
    } else {
        rbusError_t::RBUS_ERROR_SUCCESS
    }
}

struct Provider {
    bus: RBusHandle,
    raw: RBusLibraryRaw,
    component: CString,
    event: CString,
    denied: CString,
}

impl Provider {
    fn new(library: &RBusLibrary) -> anyhow::Result<Self> {
        let id = NEXT_PROVIDER.fetch_add(1, Ordering::Relaxed);
        Self::open(
            library,
            CString::new(format!("Device.EventTest{}_{id}", std::process::id()))?,
        )
    }

    fn open(library: &RBusLibrary, component: CString) -> anyhow::Result<Self> {
        let bus = RBusHandle::open(library, &component)?;
        let raw = unsafe { RBusLibraryRaw::load()? };
        let event = CString::new(format!("{}.Changed!", component.to_str()?))?;
        let denied = CString::new(format!("{}.Denied!", component.to_str()?))?;
        let elements: Vec<_> = [&event, &denied]
            .into_iter()
            .map(|name| rbusDataElement_t {
                name: name.as_ptr().cast_mut(),
                type_: rbusElementType_t::RBUS_ELEMENT_TYPE_EVENT,
                cbTable: rbusCallbackTable_t {
                    getHandler: None,
                    setHandler: None,
                    tableAddRowHandler: None,
                    tableRemoveRowHandler: None,
                    eventSubHandler: Some(allow_subscription),
                    methodHandler: std::ptr::null_mut(),
                },
            })
            .collect();
        let result = unsafe {
            raw.rbus_regDataElements(
                bus.to_raw().cast_mut().cast(),
                elements.len() as i32,
                elements.as_ptr().cast_mut(),
            )
        };
        assert_eq!(result, rbusError_t::RBUS_ERROR_SUCCESS);
        Ok(Self {
            bus,
            raw,
            component,
            event,
            denied,
        })
    }

    fn client(&self) -> anyhow::Result<RBusHandle> {
        Ok(RBusHandle::open(
            self.bus.library(),
            &CString::new(format!("{}.Client", self.component.to_str()?))?,
        )?)
    }

    fn publish(&self, value: i32) -> rbusError_t {
        unsafe {
            let mut object = std::ptr::null_mut();
            self.raw
                .rbusObject_Init(&mut object, c"event-data".as_ptr());
            let value_handle = self.raw.rbusValue_Init(std::ptr::null_mut());
            self.raw.rbusValue_SetInt32(value_handle, value);
            self.raw
                .rbusObject_SetValue(object, c"value".as_ptr(), value_handle);
            self.raw.rbusValue_Release(value_handle);
            let mut event = rbusEvent_t {
                name: self.event.as_ptr(),
                type_: rbusEventType_t::RBUS_EVENT_GENERAL,
                data: object,
            };
            let result = self
                .raw
                .rbusEvent_Publish(self.bus.to_raw().cast_mut().cast(), &mut event);
            self.raw.rbusObject_Release(object);
            result
        }
    }
}

struct IgnoreEvent;

impl RBusEventHandler for IgnoreEvent {
    fn on_event(_: &RBusEventRef<'_>) {}
}

#[test]
fn receives_payload_rejects_duplicates_and_unsubscribes() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    static SENDER: OnceLock<mpsc::Sender<(CString, RBusEventType, i32, usize)>> = OnceLock::new();
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    struct Handler;

    impl RBusEventHandler for Handler {
        fn on_event(event: &RBusEventRef<'_>) {
            let value = event
                .with_data(|data| data.get_property(c"value").unwrap().get::<i32>().unwrap())
                .expect("missing event data");
            let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            SENDER
                .get()
                .unwrap()
                .send((event.name().to_owned(), event.kind(), value, count))
                .unwrap();
        }
    }

    let provider = Provider::new(&library)?;
    let bus = provider.client()?;
    let (sender, receiver) = mpsc::channel();
    SENDER.set(sender).unwrap();
    let subscription = bus.subscribe_event::<Handler>(&provider.event)?;
    assert!(matches!(
        bus.subscribe_event::<IgnoreEvent>(&provider.event),
        Err(RBusError::SubscriptionAlreadyExists)
    ));
    for count in 1..=2 {
        assert_eq!(provider.publish(42), rbusError_t::RBUS_ERROR_SUCCESS);
        assert_eq!(
            receiver.recv_timeout(WAIT)?,
            (provider.event.clone(), RBusEventType::General, 42, count)
        );
    }
    drop(subscription);
    assert_eq!(provider.publish(43), rbusError_t::RBUS_ERROR_NOSUBSCRIBERS);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    {
        let _subscription = bus.subscribe_event::<Handler>(&provider.event)?;
        assert_eq!(provider.publish(44), rbusError_t::RBUS_ERROR_SUCCESS);
        assert_eq!(
            receiver.recv_timeout(WAIT)?,
            (provider.event.clone(), RBusEventType::General, 44, 3)
        );
    }
    assert_eq!(provider.publish(45), rbusError_t::RBUS_ERROR_NOSUBSCRIBERS);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    Ok(())
}

#[test]
fn shared_handler_identifies_each_connection() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    static SENDER: OnceLock<mpsc::Sender<usize>> = OnceLock::new();
    struct Handler;

    impl RBusEventHandler for Handler {
        fn on_event(event: &RBusEventRef<'_>) {
            SENDER
                .get()
                .unwrap()
                .send(event.handle().to_raw().addr())
                .unwrap();
        }
    }

    let provider = Provider::new(&library)?;
    let first = provider.client()?;
    let second = RBusHandle::open(
        &library,
        &CString::new(format!("{}.SecondClient", provider.component.to_str()?))?,
    )?;
    let (sender, receiver) = mpsc::channel();
    SENDER.set(sender).unwrap();
    let _first_subscription = first.subscribe_event::<Handler>(&provider.event)?;
    let _second_subscription = second.subscribe_event::<Handler>(&provider.event)?;
    assert_eq!(provider.publish(1), rbusError_t::RBUS_ERROR_SUCCESS);
    let mut received = [receiver.recv_timeout(WAIT)?, receiver.recv_timeout(WAIT)?];
    let mut expected = [first.to_raw().addr(), second.to_raw().addr()];
    received.sort_unstable();
    expected.sort_unstable();
    assert_eq!(received, expected);
    Ok(())
}

#[test]
fn subscribes_to_native_property_value_changes() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    static SENDER: OnceLock<mpsc::Sender<(RBusEventType, i32, i32)>> = OnceLock::new();
    struct Handler;

    impl RBusEventHandler for Handler {
        fn on_event(event: &RBusEventRef<'_>) {
            let (old, new) = event
                .with_data(|data| {
                    let old = data
                        .get_property(c"oldValue")
                        .unwrap()
                        .get::<i32>()
                        .unwrap();
                    let new = data.get_property(c"value").unwrap().get::<i32>().unwrap();
                    (old, new)
                })
                .expect("missing event data");
            SENDER
                .get()
                .unwrap()
                .send((event.kind(), old, new))
                .unwrap();
        }
    }

    let provider = Provider::new(&library)?;
    let name = CString::new(format!("{}.Value", provider.component.to_str()?))?;
    PROPERTY_VALUE.store(10, Ordering::Relaxed);
    provider
        .bus
        .register_data_elements(&[RBusDataElement::property_ro::<PolledProperty>(&name)])?;
    let bus = provider.client()?;
    let (sender, receiver) = mpsc::channel();
    SENDER.set(sender).unwrap();
    let _subscription = bus.subscribe_event::<Handler>(&name)?;
    PROPERTY_VALUE.store(20, Ordering::Relaxed);
    // Some native RBus versions poll every 30 seconds.
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(40))?,
        (RBusEventType::ValueChanged, 10, 20)
    );
    Ok(())
}

#[test]
fn failed_subscriptions_can_be_retried_and_reject_invalid_timeouts() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    let provider = Provider::new(&library)?;
    let bus = provider.client()?;
    for _ in 0..2 {
        assert!(matches!(
            bus.subscribe_event::<IgnoreEvent>(&provider.denied),
            Err(RBusError::AccessNotAllowed)
        ));
    }
    for timeout in [Duration::MAX, Duration::from_secs(i32::MAX as u64)] {
        assert!(matches!(
            bus.subscribe_event_with_options::<IgnoreEvent>(
                &provider.event,
                RBusSubscribeOptions { timeout },
            ),
            Err(RBusError::InvalidInput)
        ));
    }
    let _subscription = bus.subscribe_event::<IgnoreEvent>(&provider.event)?;
    Ok(())
}

#[test]
fn callback_panics_do_not_unwind_through_c() -> anyhow::Result<()> {
    let Some(library) = load_library()? else {
        return Ok(());
    };
    static SENDER: OnceLock<mpsc::Sender<()>> = OnceLock::new();
    struct PanickingHandler;
    struct Handler;
    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("test panic payload destructor");
        }
    }

    impl RBusEventHandler for PanickingHandler {
        fn on_event(_: &RBusEventRef<'_>) {
            SENDER.get().unwrap().send(()).unwrap();
            std::panic::panic_any(PanicOnDrop);
        }
    }

    impl RBusEventHandler for Handler {
        fn on_event(_: &RBusEventRef<'_>) {
            SENDER.get().unwrap().send(()).unwrap();
        }
    }

    let provider = Provider::new(&library)?;
    let bus = provider.client()?;
    let (sender, receiver) = mpsc::channel();
    SENDER.set(sender).unwrap();
    let subscription = bus.subscribe_event::<PanickingHandler>(&provider.event)?;
    assert_eq!(provider.publish(1), rbusError_t::RBUS_ERROR_SUCCESS);
    receiver.recv_timeout(WAIT)?;
    drop(subscription);
    let _subscription = bus.subscribe_event::<Handler>(&provider.event)?;
    assert_eq!(provider.publish(2), rbusError_t::RBUS_ERROR_SUCCESS);
    receiver.recv_timeout(WAIT)?;
    Ok(())
}
