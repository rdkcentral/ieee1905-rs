use rbus_sys::*;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error, Copy, Clone)]
pub enum RBusValueGetError {
    #[error("Wrong type of value requested")]
    BadType,
    #[error("Value not found")]
    NotFound,
    #[error("Value us null")]
    Null,
    #[error("Unexpected error: {0:?}")]
    Unexpected(rbusValueError_t),
}

impl RBusValueGetError {
    pub(super) fn map<T>(error: rbusValueError_t, success: T) -> Result<T, Self> {
        match error {
            rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS => Ok(success),
            rbusValueError_t::RBUS_VALUE_ERROR_TYPE => Err(Self::BadType),
            rbusValueError_t::RBUS_VALUE_ERROR_NOT_FOUND => Err(Self::BadType),
            rbusValueError_t::RBUS_VALUE_ERROR_NULL => Err(Self::BadType),
            e => Err(Self::Unexpected(e)),
        }
    }
}
