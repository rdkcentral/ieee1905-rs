use crate::RBusValueGetError;
use rbus_sys::*;
use std::os::raw::c_uint;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RBusError {
    #[error("General Error")]
    GeneralError,
    #[error("Invalid Input")]
    InvalidInput,
    #[error("Bus not initialized")]
    NotInitialized,
    #[error("Running out of resources")]
    OutOfResources,
    #[error("Destination element not found")]
    DestinationNotFound,
    #[error("Destination element not reachable")]
    DestinationNotReachable,
    #[error("Destination failed to respond")]
    DestinationResponseFailure,
    #[error("Invalid destination response")]
    InvalidDestinationResponse,
    #[error("Invalid operation")]
    InvalidOperation,
    #[error("Invalid event")]
    InvalidEvent,
    #[error("Invalid handle")]
    InvalidHandle,
    #[error("Session already opened")]
    SessionAlreadyExists,
    #[error("Component name already exists")]
    ComponentNameDuplication,
    #[error("One or more element name(s) were previously registered")]
    ElementNameDuplication,
    #[error("No names were provided in the name field")]
    ElementNameMissing,
    #[error("A bus connection for this component name was not previously opened")]
    ComponentDoesNotExists,
    #[error("One or more data element name(s) do not currently have a valid registration")]
    ElementDoesNotExists,
    #[error("Access to the requested data element was not permitted by the provider component")]
    AccessNotAllowed,
    #[error("The Context is not same as what was sent in the get callback handler")]
    InvalidContext,
    #[error("The operation timed out")]
    Timeout,
    #[error("The method request will be handle asynchronously by provider")]
    AsyncResponse,
    #[error("Invalid method")]
    InvalidMethod,
    #[error("No subscribers present")]
    NoSubscribers,
    #[error("The subscription already exists")]
    SubscriptionAlreadyExists,
    #[error("Invalid namespace as per standard")]
    InvalidNamespace,
    #[error("Direct connection not exist")]
    DirectConnectionNotExist,
    #[error("Set to the requested data element was not permitted by the provider component")]
    WotWritable,
    #[error("Get to the requested data element was not permitted by the provider component")]
    NotReadable,
    #[error("Invalid parameter type")]
    InvalidParameterType,
    #[error("Invalid parameter value")]
    InvalidParameterValue,
    #[error("Unexpected error: {0}")]
    Unexpected(c_uint),
}

impl RBusError {
    pub(crate) fn map<T>(error: rbusError_t, success: impl FnOnce() -> T) -> Result<T, Self> {
        Err(match error {
            rbusError_t::RBUS_ERROR_SUCCESS => return Ok(success()),
            rbusError_t::RBUS_ERROR_BUS_ERROR => Self::GeneralError,
            rbusError_t::RBUS_ERROR_INVALID_INPUT => Self::InvalidInput,
            rbusError_t::RBUS_ERROR_NOT_INITIALIZED => Self::NotInitialized,
            rbusError_t::RBUS_ERROR_OUT_OF_RESOURCES => Self::OutOfResources,
            rbusError_t::RBUS_ERROR_DESTINATION_NOT_FOUND => Self::DestinationNotFound,
            rbusError_t::RBUS_ERROR_DESTINATION_NOT_REACHABLE => Self::DestinationNotReachable,
            rbusError_t::RBUS_ERROR_DESTINATION_RESPONSE_FAILURE => {
                Self::DestinationResponseFailure
            }
            rbusError_t::RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION => {
                Self::InvalidDestinationResponse
            }
            rbusError_t::RBUS_ERROR_INVALID_OPERATION => Self::InvalidOperation,
            rbusError_t::RBUS_ERROR_INVALID_EVENT => Self::InvalidEvent,
            rbusError_t::RBUS_ERROR_INVALID_HANDLE => Self::InvalidHandle,
            rbusError_t::RBUS_ERROR_SESSION_ALREADY_EXIST => Self::SessionAlreadyExists,
            rbusError_t::RBUS_ERROR_COMPONENT_NAME_DUPLICATE => Self::ComponentNameDuplication,
            rbusError_t::RBUS_ERROR_ELEMENT_NAME_DUPLICATE => Self::ElementNameDuplication,
            rbusError_t::RBUS_ERROR_ELEMENT_NAME_MISSING => Self::ElementNameMissing,
            rbusError_t::RBUS_ERROR_COMPONENT_DOES_NOT_EXIST => Self::ComponentDoesNotExists,
            rbusError_t::RBUS_ERROR_ELEMENT_DOES_NOT_EXIST => Self::ElementDoesNotExists,
            rbusError_t::RBUS_ERROR_ACCESS_NOT_ALLOWED => Self::AccessNotAllowed,
            rbusError_t::RBUS_ERROR_INVALID_CONTEXT => Self::InvalidContext,
            rbusError_t::RBUS_ERROR_TIMEOUT => Self::Timeout,
            rbusError_t::RBUS_ERROR_ASYNC_RESPONSE => Self::AsyncResponse,
            rbusError_t::RBUS_ERROR_INVALID_METHOD => Self::InvalidMethod,
            rbusError_t::RBUS_ERROR_NOSUBSCRIBERS => Self::NoSubscribers,
            rbusError_t::RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST => Self::SubscriptionAlreadyExists,
            rbusError_t::RBUS_ERROR_INVALID_NAMESPACE => Self::InvalidNamespace,
            rbusError_t::RBUS_ERROR_DIRECT_CON_NOT_EXIST => Self::DirectConnectionNotExist,
            rbusError_t::RBUS_ERROR_NOT_WRITABLE => Self::WotWritable,
            rbusError_t::RBUS_ERROR_NOT_READABLE => Self::NotReadable,
            rbusError_t::RBUS_ERROR_INVALID_PARAMETER_TYPE => Self::InvalidParameterType,
            rbusError_t::RBUS_ERROR_INVALID_PARAMETER_VALUE => Self::InvalidParameterValue,
            e => Self::Unexpected(e.0),
        })
    }

    pub(crate) fn to_raw(&self) -> rbusError_t {
        match self {
            Self::GeneralError => rbusError_t::RBUS_ERROR_BUS_ERROR,
            Self::InvalidInput => rbusError_t::RBUS_ERROR_INVALID_INPUT,
            Self::NotInitialized => rbusError_t::RBUS_ERROR_NOT_INITIALIZED,
            Self::OutOfResources => rbusError_t::RBUS_ERROR_OUT_OF_RESOURCES,
            Self::DestinationNotFound => rbusError_t::RBUS_ERROR_DESTINATION_NOT_FOUND,
            Self::DestinationNotReachable => rbusError_t::RBUS_ERROR_DESTINATION_NOT_REACHABLE,
            Self::DestinationResponseFailure => {
                rbusError_t::RBUS_ERROR_DESTINATION_RESPONSE_FAILURE
            }
            Self::InvalidDestinationResponse => {
                rbusError_t::RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION
            }
            Self::InvalidOperation => rbusError_t::RBUS_ERROR_INVALID_OPERATION,
            Self::InvalidEvent => rbusError_t::RBUS_ERROR_INVALID_EVENT,
            Self::InvalidHandle => rbusError_t::RBUS_ERROR_INVALID_HANDLE,
            Self::SessionAlreadyExists => rbusError_t::RBUS_ERROR_SESSION_ALREADY_EXIST,
            Self::ComponentNameDuplication => rbusError_t::RBUS_ERROR_COMPONENT_NAME_DUPLICATE,
            Self::ElementNameDuplication => rbusError_t::RBUS_ERROR_ELEMENT_NAME_DUPLICATE,
            Self::ElementNameMissing => rbusError_t::RBUS_ERROR_ELEMENT_NAME_MISSING,
            Self::ComponentDoesNotExists => rbusError_t::RBUS_ERROR_COMPONENT_DOES_NOT_EXIST,
            Self::ElementDoesNotExists => rbusError_t::RBUS_ERROR_ELEMENT_DOES_NOT_EXIST,
            Self::AccessNotAllowed => rbusError_t::RBUS_ERROR_ACCESS_NOT_ALLOWED,
            Self::InvalidContext => rbusError_t::RBUS_ERROR_INVALID_CONTEXT,
            Self::Timeout => rbusError_t::RBUS_ERROR_TIMEOUT,
            Self::AsyncResponse => rbusError_t::RBUS_ERROR_ASYNC_RESPONSE,
            Self::InvalidMethod => rbusError_t::RBUS_ERROR_INVALID_METHOD,
            Self::NoSubscribers => rbusError_t::RBUS_ERROR_NOSUBSCRIBERS,
            Self::SubscriptionAlreadyExists => rbusError_t::RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST,
            Self::InvalidNamespace => rbusError_t::RBUS_ERROR_INVALID_NAMESPACE,
            Self::DirectConnectionNotExist => rbusError_t::RBUS_ERROR_DIRECT_CON_NOT_EXIST,
            Self::WotWritable => rbusError_t::RBUS_ERROR_NOT_WRITABLE,
            Self::NotReadable => rbusError_t::RBUS_ERROR_NOT_READABLE,
            Self::InvalidParameterType => rbusError_t::RBUS_ERROR_INVALID_PARAMETER_TYPE,
            Self::InvalidParameterValue => rbusError_t::RBUS_ERROR_INVALID_PARAMETER_VALUE,
            Self::Unexpected(e) => rbusError_t(*e),
        }
    }
}

#[derive(Debug, Error)]
pub enum RBusGetError {
    #[error("{0}")]
    RBus(RBusError),
    #[error("{0}")]
    RBusValue(RBusValueGetError),
}
