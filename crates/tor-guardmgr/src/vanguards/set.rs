//! Vanguard sets

use std::cmp::Ordering;
use std::time::SystemTime;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use tor_linkspec::RelayIds;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::RelayExclusion;

use std::sync::Weak;

/// A vanguard relay.
//
// TODO HS-VANGUARDS: this is currently just a Relay newtype (if it doesn't grow any additional
// fields, we might want to consider removing it and using Relay instead).
#[derive(Clone, amplify::Getters)]
pub struct Vanguard<'a> {
    /// The relay.
    relay: Relay<'a>,
}

/// An identifier for a time-bound vanguard.
///
/// Each vanguard [`Layer`](crate::vanguards::Layer) consists of a [`VanguardSet`],
/// which contains multiple `TimeBoundVanguard`s.
///
/// A [`VanguardSet`]'s `TimeBoundVanguard`s are rotated
/// by [`VanguardMgr`](crate::vanguards::VanguardMgr) as soon as they expire.
/// If [Full](crate::vanguards::VanguardMode) vanguards are in use,
/// the `TimeBoundVanguard`s from all layers are persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)] //
pub(crate) struct TimeBoundVanguard {
    /// The ID of this relay.
    pub(super) id: RelayIds,
    /// When to stop using this relay as a vanguard.
    pub(super) when: SystemTime,
}

// TODO(#1342): derive all of these?
impl Ord for TimeBoundVanguard {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed, because we want the earlier
        // `TimeBoundVanguard` to be "greater".
        self.when.cmp(&other.when).reverse()
    }
}

impl PartialOrd for TimeBoundVanguard {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TimeBoundVanguard {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when
    }
}

impl Eq for TimeBoundVanguard {}

/// A set of vanguards, for use in a particular [`Layer`](crate::vanguards::Layer).
#[derive(Debug, Clone)] //
#[allow(unused)] // TODO HS-VANGUARDS
pub(super) struct VanguardSet {
    /// The time-bound vanguards of a given [`Layer`](crate::vanguards::Layer).
    vanguards: Vec<Weak<TimeBoundVanguard>>,
    /// The number of vanguards we would like to have in this set.
    target: usize,
}

impl VanguardSet {
    /// Create a new vanguard set with the specified target size.
    pub(super) fn new(target: usize) -> Self {
        Self {
            vanguards: Default::default(),
            target,
        }
    }

    /// Pick a relay from this set.
    ///
    /// See [`VanguardMgr::select_vanguard`](crate::vanguards::VanguardMgr::select_vanguard)
    /// for more information.
    pub(super) fn pick_relay<'a, R: RngCore>(
        &self,
        _rng: &mut R,
        _netdir: &'a NetDir,
        _neighbor_exclusion: &RelayExclusion<'a>,
    ) -> Option<Vanguard<'a>> {
        todo!()
    }
}
