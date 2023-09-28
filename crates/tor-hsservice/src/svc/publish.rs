//! Publish and maintain onion service descriptors

#![allow(clippy::needless_pass_by_value)] // TODO HSS REMOVE.

mod backoff;
mod descriptor;
mod reactor;

use futures::task::SpawnExt;
use postage::watch;
use std::sync::Arc;
use tor_keymgr::KeyMgr;
use tracing::warn;

use tor_error::warn_report;
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::OnionServiceConfig;
use crate::{ipt_set::IptsPublisherView, StartupError};

use reactor::Reactor;

pub(crate) use reactor::{Mockable, Real};

/// A handle for the Hsdir Publisher for an onion service.
///
/// This handle represents a set of tasks that identify the hsdirs for each
/// relevant time period, construct descriptors, publish them, and keep them
/// up-to-date.
#[must_use = "If you don't call launch() on the publisher, it won't publish any descriptors."]
pub(crate) struct Publisher<R: Runtime, M: Mockable> {
    /// The runtime.
    runtime: R,
    /// The HsId of the service.
    //
    // TODO HSS: read this from the KeyMgr instead?
    hsid: HsId,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// Mockable state.
    ///
    /// This is used for launching circuits and for obtaining random number generators.
    mockable: M,
    /// The onion service config.
    config: Arc<OnionServiceConfig>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    /// The key manager.
    keymgr: Arc<KeyMgr>,
}

impl<R: Runtime, M: Mockable> Publisher<R, M> {
    /// Create a new publisher.
    ///
    /// When it launches, it will know no keys or introduction points,
    /// and will therefore not upload any descriptors.
    ///
    /// The publisher won't start publishing until you call [`Publisher::launch`].
    //
    // TODO HSS: perhaps we don't need both config and config_rx (we could read the initial config
    // value from config_rx).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: impl Into<M>,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
        keymgr: Arc<KeyMgr>,
    ) -> Self {
        let config = config_rx.borrow().clone();
        Self {
            runtime,
            hsid,
            dir_provider,
            mockable: mockable.into(),
            config,
            ipt_watcher,
            config_rx,
            keymgr,
        }
    }

    /// Launch the publisher reactor.
    pub(crate) fn launch(self) -> Result<(), StartupError> {
        let Publisher {
            runtime,
            hsid,
            dir_provider,
            mockable,
            config,
            ipt_watcher,
            config_rx,
            keymgr,
        } = self;

        let reactor = Reactor::new(
            runtime.clone(),
            hsid,
            dir_provider,
            mockable,
            config,
            ipt_watcher,
            config_rx,
            keymgr,
        );

        runtime
            .spawn(async move {
                match reactor.run().await {
                    Ok(()) => warn!("the publisher reactor has shut down"),
                    Err(e) => warn_report!(e, "the publisher reactor has shut down"),
                }
            })
            .map_err(|e| StartupError::Spawn {
                spawning: "publisher reactor task",
                cause: e.into(),
            })?;

        Ok(())
    }

    /// Inform this publisher that its set of keys has changed.
    ///
    /// TODO HSS: Either this needs to take new keys as an argument, or there
    /// needs to be a source of keys (including public keys) in Publisher.
    pub(crate) fn new_hs_keys(&self, keys: ()) {
        todo!()
    }

    /// Return our current status.
    //
    // TODO HSS: There should also be a postage::Watcher -based stream of status
    // change events.
    pub(crate) fn status(&self) -> PublisherStatus {
        todo!()
    }

    // TODO HSS: We may also need to update descriptors based on configuration
    // or authentication changes.
}

/// Current status of our attempts to publish an onion service descriptor.
#[derive(Debug, Clone)]
pub(crate) struct PublisherStatus {
    // TODO HSS add fields
}

//
// Our main loop has to look something like:

// Whenever time period or keys or netdir changes: Check whether our list of
// HsDirs has changed.  If it is, add and/or remove hsdirs as needed.

// "when learning about new keys, new intro points, or new configurations,
// or whenever the time period changes: Mark descriptors dirty."

// Whenever descriptors are dirty, we have enough info to generate
// descriptors, and we aren't upload-rate-limited: Generate new descriptors
// and mark descriptors clean.  Mark all hsdirs as needing new versions of
// this descriptor.

// While any hsdir does not have the latest version of its any descriptor:
// upload it.  Retry with usual timeouts on failure."

// TODO HSS: tests
