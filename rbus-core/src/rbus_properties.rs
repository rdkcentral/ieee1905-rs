use crate::{RBusLibrary, RBusProperty};
use rbus_sys::rbusProperty_t;
use std::iter::FusedIterator;

///
/// A retained list of properties, which may be empty.
/// Properties and links are shared with the object.
///
pub struct RBusProperties {
    head: Option<RBusProperty>,
}

impl RBusProperties {
    pub(crate) fn retain(library: &RBusLibrary, handle: rbusProperty_t) -> Self {
        let head = if handle.is_null() {
            None
        } else {
            Some(RBusProperty::retain(library, handle))
        };
        Self { head }
    }

    ///
    /// Return whether the collection has no properties.
    ///
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    ///
    /// Iterate over retained properties in native list order.
    /// The iterator and returned properties may outlive the collection.
    /// Changes to links not yet visited may affect iteration.
    ///
    pub fn iter(&self) -> RBusPropertyIter {
        RBusPropertyIter {
            next: self.head.clone(),
        }
    }
}

///
/// An iterator that retains ownership of its next property.
///
pub struct RBusPropertyIter {
    next: Option<RBusProperty>,
}

impl Iterator for RBusPropertyIter {
    type Item = RBusProperty;

    fn next(&mut self) -> Option<Self::Item> {
        let property = self.next.take()?;
        // SAFETY: `property` owns a reference to this non-null native node,
        // which owns its next link. Retain that link before yielding the node.
        let handle = unsafe {
            property
                .library
                .as_raw()
                .rbusProperty_GetNext(property.handle)
        };
        if !handle.is_null() {
            self.next = Some(RBusProperty::retain(&property.library, handle));
        }
        Some(property)
    }
}

impl FusedIterator for RBusPropertyIter {}
