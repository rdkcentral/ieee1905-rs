#![allow(warnings)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub use libloading;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
