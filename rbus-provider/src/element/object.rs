use crate::element::elements::RBusProviderElements;
use crate::element::{
    RBusProviderElement, RBusProviderElementError, RBusProviderGetterArgsInner,
    RBusProviderTableSyncArgsInner,
};
use crate::{IntoCowBStr, join_path};
use bstr::BStr;
use std::borrow::Cow;
use std::ffi::CString;

// noinspection ALL
///
/// Create new object builder instance
///
pub fn rbus_object<N>(name: N, content: impl RBusProviderElement) -> impl RBusProviderElement
where
    N: IntoCowBStr,
{
    RBusProviderObject {
        path: Default::default(),
        name: name.into_cow_b_str(),
        content,
    }
}

///
/// Object type element
///
/// It doesn't contain any logic except being a part of the path
///
pub(crate) struct RBusProviderObject<Content> {
    path: CString,
    name: Cow<'static, BStr>,
    content: Content,
}

impl<Content> RBusProviderElement for RBusProviderObject<Content>
where
    Content: RBusProviderElement,
{
    type UserData = Content::UserData;

    fn initialize(&mut self, parent: &BStr) {
        self.path = join_path(&[parent, &self.name]);
        self.content.initialize(self.path.as_bytes().into());
    }

    fn collect_data_elements<'a>(&'a self, target: &mut RBusProviderElements<'a>) {
        self.content.collect_data_elements(target);
    }

    fn invoke_get(
        &mut self,
        mut path: &[&BStr],
        args: RBusProviderGetterArgsInner<'_, Self::UserData>,
    ) -> Result<(), RBusProviderElementError> {
        if path.split_off_first() != Some(&self.name.as_ref()) {
            return Err(RBusProviderElementError::WrongElement);
        }
        self.content.invoke_get(path, args)
    }

    fn invoke_table_sync(
        &mut self,
        mut path: &[&BStr],
        args: RBusProviderTableSyncArgsInner<'_, Self::UserData>,
    ) -> Result<(), RBusProviderElementError> {
        if path.split_off_first() != Some(&self.name.as_ref()) {
            return Err(RBusProviderElementError::WrongElement);
        }
        self.content.invoke_table_sync(path, args)
    }
}
