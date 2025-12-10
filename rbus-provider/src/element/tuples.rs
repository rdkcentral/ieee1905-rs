use crate::element::elements::RBusProviderElements;
use crate::element::{
    RBusProviderElement, RBusProviderElementError, RBusProviderGetterArgsInner,
    RBusProviderTableSyncArgsInner,
};
use bstr::BStr;

///
/// Define tuple as a provider element
///
/// This is the major part of the DSL, which provides elements grouping support
///
macro_rules! define {
    ($($arg:ident),*) => {
        #[allow(unused, non_snake_case, non_camel_case_types, private_interfaces)]
        impl<$($arg,)*> RBusProviderElement for ($($arg,)*)
        where
            $($arg: RBusProviderElement,)*
        {
            type UserData = ($($arg::UserData,)*);

            fn initialize(&mut self, parent: &BStr) {
                let ($($arg,)*) = self;
                $($arg.initialize(parent);)*
            }

            fn collect_data_elements<'a>(&'a self, target: &mut RBusProviderElements<'a>) {
                let ($($arg,)*) = self;
                $($arg.collect_data_elements(target);)*
            }

            fn invoke_get(
                &mut self,
                path: &[&BStr],
                args: RBusProviderGetterArgsInner<'_, Self::UserData>,
            ) -> Result<(), RBusProviderElementError> {
                struct __InnerTupleStruct<'a, $($arg),*> {
                    $($arg: &'a mut $arg,)*
                }

                let user_data = {
                    let ($($arg,)*) = args.user_data;
                    __InnerTupleStruct { $($arg),* }
                };

                let ($($arg,)*) = self;
                $(
                {
                    let result = $arg.invoke_get(path, RBusProviderGetterArgsInner {
                        property: args.property,
                        table_idx: args.table_idx,
                        user_data: user_data.$arg,
                    });
                    let Err(RBusProviderElementError::WrongElement) = result else {
                        return result;
                    };
                }
                )*
                Err(RBusProviderElementError::WrongElement)
            }

            fn invoke_table_sync(
                &mut self,
                path: &[&BStr],
                args: RBusProviderTableSyncArgsInner<'_, Self::UserData>,
            ) -> Result<(), RBusProviderElementError> {
                struct __InnerTupleStruct<'a, $($arg),*> {
                    $($arg: &'a mut $arg,)*
                }

                let user_data = {
                    let ($($arg,)*) = args.user_data;
                    __InnerTupleStruct { $($arg),* }
                };

                let ($($arg,)*) = self;
                $(
                {
                    let result = $arg.invoke_table_sync(path, RBusProviderTableSyncArgsInner {
                        handle: args.handle,
                        full_path: args.full_path,
                        table_idx: args.table_idx,
                        user_data: user_data.$arg,
                    });
                    let Err(RBusProviderElementError::WrongElement) = result else {
                        return result;
                    };
                }
                )*
                Err(RBusProviderElementError::WrongElement)
            }
        }
    }
}

define!(x1);
define!(x1, x2);
define!(x1, x2, x3);
define!(x1, x2, x3, x4);
define!(x1, x2, x3, x4, x5);
define!(x1, x2, x3, x4, x5, x6);
define!(x1, x2, x3, x4, x5, x6, x7);
define!(x1, x2, x3, x4, x5, x6, x7, x8);
define!(x1, x2, x3, x4, x5, x6, x7, x8, x9);
define!(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10);
define!(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11);
define!(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12);
