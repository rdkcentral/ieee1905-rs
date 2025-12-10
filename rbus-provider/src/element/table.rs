use crate::element::elements::RBusProviderElements;
use crate::element::{
    RBusProviderElement, RBusProviderElementError, RBusProviderGetterArgsInner,
    RBusProviderTableSyncArgsInner,
};
use crate::{IntoCowBStr, join_path};
use bstr::BStr;
use rbus_core::RBusError;
use std::borrow::Cow;
use std::ffi::CString;

// noinspection ALL
///
/// Create new table builder instance
///
pub fn rbus_table<N, T>(name: N, handler: T) -> RBusProviderTableBuilder<N, T> {
    RBusProviderTableBuilder(name, handler)
}

///
/// Table builder
///
pub struct RBusProviderTableBuilder<N, T>(N, T);

impl<N, T> RBusProviderTableBuilder<N, T> {
    ///
    /// Create new table instance
    ///
    pub fn content<C>(self, content: C) -> impl RBusProviderElement
    where
        N: IntoCowBStr,
        C: RBusProviderElement,
        T: RBusProviderTableSync,
    {
        RBusProviderTable {
            path: Default::default(),
            name: self.0.into_cow_b_str(),
            sync: self.1,
            content,
        }
    }
}

///
/// Table type element
///
pub(crate) struct RBusProviderTable<Content, FSync> {
    path: CString,
    name: Cow<'static, BStr>,
    sync: FSync,
    content: Content,
}

impl<Content, FSync> RBusProviderElement for RBusProviderTable<Content, FSync>
where
    Content: RBusProviderElement,
    FSync: RBusProviderTableSync,
{
    type UserData = (FSync::UserData, Vec<Content::UserData>);

    fn initialize(&mut self, parent: &BStr) {
        self.path = join_path(&[parent, &self.name]);

        let item_path = join_path(&[self.path.as_bytes().into(), "{i}".into()]);
        self.content.initialize(item_path.as_bytes().into());
    }

    fn collect_data_elements<'a>(&'a self, target: &mut RBusProviderElements<'a>) {
        target.push_table(&self.path);
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

        let Some(index) = path.split_off_first() else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };
        let Ok(index) = str::from_utf8(index) else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };
        let Ok(index) = index.parse::<u32>() else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };

        let Some(user_data) = args.user_data.1.get_mut(index as usize) else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };

        args.table_idx.push(index);

        self.content.invoke_get(
            path,
            RBusProviderGetterArgsInner {
                property: args.property,
                table_idx: args.table_idx,
                user_data,
            },
        )
    }

    fn invoke_table_sync(
        &mut self,
        mut path: &[&BStr],
        args: RBusProviderTableSyncArgsInner<'_, Self::UserData>,
    ) -> Result<(), RBusProviderElementError> {
        if path.split_off_first() != Some(&self.name.as_ref()) {
            return Err(RBusProviderElementError::WrongElement);
        }

        if path.is_empty() || path == &["{i}"] {
            let table_path = join_path(&[args.full_path]);

            let len_new = self.sync.len(RBusProviderTableSyncArgs {
                table_idx: args.table_idx,
                user_data: &mut args.user_data.0,
            })?;

            let len_old = args.user_data.1.len() as u32;
            for index in len_old..len_new {
                args.handle.register_table_row(&table_path, index, None)?;
                args.user_data.1.push(Content::UserData::default());
            }
            for index in len_new..len_old {
                let row_path = join_path(&[
                    self.path.as_bytes().into(),
                    format!("{index}").as_bytes().into(),
                ]);
                args.handle.unregister_table_row(&row_path)?;
                args.user_data.1.pop();
            }
            return Ok(());
        }

        let Some(index) = path.split_off_first() else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };
        let Ok(index) = str::from_utf8(index) else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };
        let Ok(index) = index.parse::<u32>() else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };

        let Some(user_data) = args.user_data.1.get_mut(index as usize) else {
            return Err(RBusProviderElementError::RBus(
                RBusError::ElementDoesNotExists,
            ));
        };

        args.table_idx.push(index);

        self.content.invoke_table_sync(
            path,
            RBusProviderTableSyncArgsInner {
                handle: args.handle,
                full_path: args.full_path,
                table_idx: args.table_idx,
                user_data,
            },
        )
    }
}

///
/// Arguments used when handling table sync
///
pub struct RBusProviderTableSyncArgs<'a, UserData> {
    pub table_idx: &'a [u32],
    pub user_data: &'a mut UserData,
}

///
/// Table sync handler
///
pub trait RBusProviderTableSync: Send + 'static {
    type UserData: Default + Send + 'static;

    ///
    /// Returns number of items in the table
    ///
    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError>;
}
