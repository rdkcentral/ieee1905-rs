use crate::element::elements::RBusProviderElements;
use crate::element::{
    RBusProviderElement, RBusProviderElementError, RBusProviderGetterArgsInner,
    RBusProviderTableSyncArgsInner,
};
use crate::{IntoCowBStr, join_path};
use bstr::BStr;
use rbus_core::{RBusError, RBusProperty};
use std::borrow::Cow;
use std::ffi::CString;

// noinspection ALL
///
/// Create new property instance
///
pub fn rbus_property<T>(name: impl IntoCowBStr, handler: T) -> impl RBusProviderElement
where
    T: RBusProviderGetter,
{
    RBusProviderProperty {
        path: Default::default(),
        name: name.into_cow_b_str(),
        getter: handler,
    }
}

///
/// Property type element
///
pub(crate) struct RBusProviderProperty<FGet> {
    path: CString,
    name: Cow<'static, BStr>,
    getter: FGet,
}

impl<FGet> RBusProviderElement for RBusProviderProperty<FGet>
where
    FGet: RBusProviderGetter,
{
    type UserData = FGet::UserData;

    fn initialize(&mut self, parent: &BStr) {
        self.path = join_path(&[parent, &self.name]);
    }

    fn collect_data_elements<'a>(&'a self, target: &mut RBusProviderElements<'a>) {
        target.push_property(&self.path);
    }

    fn invoke_get(
        &mut self,
        mut path: &[&BStr],
        args: RBusProviderGetterArgsInner<'_, Self::UserData>,
    ) -> Result<(), RBusProviderElementError> {
        let Some(path_name) = path.split_off_first() else {
            return Err(RBusProviderElementError::WrongElement);
        };
        if path_name != &self.name.as_ref() {
            return Err(RBusProviderElementError::WrongElement);
        }
        if !path.is_empty() {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        }
        self.getter.get(RBusProviderGetterArgs {
            property: args.property,
            path_name,
            path_full: args.path_full,
            path_chunks: args.path_chunks,
            table_idx: args.table_idx,
            user_data: args.user_data,
        })?;
        Ok(())
    }

    fn invoke_table_sync(
        &mut self,
        mut path: &[&BStr],
        _args: RBusProviderTableSyncArgsInner<'_, Self::UserData>,
    ) -> Result<(), RBusProviderElementError> {
        if path.split_off_first() != Some(&self.name.as_ref()) {
            return Err(RBusProviderElementError::WrongElement);
        }
        Err(RBusProviderElementError::RBus(
            RBusError::ElementDoesNotExists,
        ))
    }
}

///
/// Arguments used when handling property getter
///
pub struct RBusProviderGetterArgs<'a, UserData> {
    pub property: &'a RBusProperty,
    pub path_name: &'a BStr,
    pub path_full: &'a BStr,
    pub path_chunks: &'a [&'a BStr],
    pub table_idx: &'a [u32],
    pub user_data: &'a mut UserData,
}

///
/// Property getter handler
///
pub trait RBusProviderGetter: Send + 'static {
    type UserData: Default + Send + 'static;

    ///
    /// Property value must be written to the property handle
    ///
    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError>;
}
