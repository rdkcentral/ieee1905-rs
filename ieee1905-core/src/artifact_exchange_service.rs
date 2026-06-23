#[cfg(feature = "artifact_exchange")]
mod http {
    pub mod client;
    mod common;
    mod fs_quota_aware_storage;
    pub mod server;
}

#[cfg(not(feature = "artifact_exchange"))]
mod stub {
    pub mod client;
    pub mod server;
}

#[cfg(feature = "artifact_exchange")]
pub use http::client;
#[cfg(feature = "artifact_exchange")]
pub use http::server;

#[cfg(not(feature = "artifact_exchange"))]
pub use stub::client;
#[cfg(not(feature = "artifact_exchange"))]
pub use stub::server;
