// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Object identifiers, versions, and the versioned objects held in the store.

use serde::{Deserialize, Serialize};

/// Uniquely identifies an object in the store.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Debug)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The version of an object.
///
/// Versions only move forward: every write creates a new `(id, version)` entry, so writebacks of
/// different transactions never overwrite each other.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Version(u64);

impl Version {
    /// The version at which objects never written to resolve.
    pub const ZERO: Self = Self(0);

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new(version: u64) -> Self {
        Self(version)
    }

    /// The version following `self`.
    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).expect("Version overflow"))
    }

    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }
}

/// A versioned object: opaque contents frozen at a specific version.
#[derive(PartialEq, Debug)]
pub struct Object {
    id: ObjectId,
    version: Version,
    contents: Vec<u8>,
}

impl Object {
    pub fn new(id: ObjectId, version: Version, contents: Vec<u8>) -> Self {
        Self {
            id,
            version,
            contents,
        }
    }

    pub fn id(&self) -> ObjectId {
        self.id
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

#[cfg(test)]
mod tests {
    use crate::object::Version;

    #[test]
    fn versions_move_forward() {
        assert!(Version::ZERO < Version::ZERO.next());
        assert_eq!(Version::new(7).next(), Version::new(8));
    }
}
