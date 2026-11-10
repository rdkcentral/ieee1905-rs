use rbus_sys::*;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
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
            rbusValueError_t::RBUS_VALUE_ERROR_NOT_FOUND => Err(Self::NotFound),
            rbusValueError_t::RBUS_VALUE_ERROR_NULL => Err(Self::Null),
            e => Err(Self::Unexpected(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_errors_preserve_native_categories() {
        for (native, expected) in [
            (rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS, Ok(())),
            (
                rbusValueError_t::RBUS_VALUE_ERROR_TYPE,
                Err(RBusValueGetError::BadType),
            ),
            (
                rbusValueError_t::RBUS_VALUE_ERROR_NOT_FOUND,
                Err(RBusValueGetError::NotFound),
            ),
            (
                rbusValueError_t::RBUS_VALUE_ERROR_NULL,
                Err(RBusValueGetError::Null),
            ),
        ] {
            assert_eq!(RBusValueGetError::map(native, ()), expected, "{native:?}");
        }
    }
}
