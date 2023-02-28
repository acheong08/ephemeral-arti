//! Implement a cache for onion descriptors and the facility to remember a bit
//! about onion service history.

use std::collections::HashMap;
use std::fmt::Debug;
use std::mem;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures::FutureExt as _;

use async_trait::async_trait;
use educe::Educe;
use postage::stream::Stream as _;
use slotmap::dense::DenseSlotMap;
use tracing::{debug, error, trace};

use tor_circmgr::isolation::Isolation;
use tor_error::{internal, Bug, ErrorReport as _};
use tor_hscrypto::pk::HsId;
use tor_rtcompat::Runtime;

use crate::{HsClientConnError, HsClientConnector, HsClientSecretKeys};

slotmap::new_key_type! {
    struct TableIndex;
}

/// Number of times we're willing to iterate round the state machine loop
///
/// This is fairly arbitrary, but we shouldn't get anywhere near it.
const MAX_ATTEMPTS: u32 = 10;

/// Hidden services;, our connections to them, and history of connections, etc.
///
/// Data structure is keyed (indexed) by:
///  * `HsId`, hidden service identity
///  * any secret keys we are to use
///  * circuit isolation
///
/// We treat different values for any of the above as completely independent,
/// except that we try isolation joining (narrowing) if everything else matches.
///
/// When deleting an entry, it should be remooved from both layers of the structure.
///
/// ```text
///           index                                         table
///           HashMap           Vec_______________          SlotMap___________________
///           |     | contains  | KS, isol | t_i |  t_i     | ServiceState / <empty> |
///   Hsid -> |  ---+---------> | KS, isol | t_i | -------> | ServiceState / <empty> |
///           |_____|           | KS, isol | t_i |          | ServiceState / <empty> |
///                             | KS, isol | t_i |          | ServiceState / <empty> |
///   KS, isol ---------------> | .........|.... |          | ServiceState / <empty> |
///             linear search   |________________|          | ...            ....    |
/// ```                                                     |________________________|
#[derive(Default, Debug)]
pub(crate) struct Services<D: MockableConnectorData> {
    /// Index, mapping key to entry in the data tble
    ///
    /// There's a HashMap from HsId.
    ///
    /// Then there is a linear search over the other key info,
    /// which can only be compared for equality/compatibility, not indexed.
    index: HashMap<HsId, Vec<IndexRecord>>,

    /// Actual table containing the state of our ideas about this service
    ///
    /// Using a slotmap allows the task, when it completes, to find the relevant
    /// place to put its results, without having to re-traverse the data structure.
    /// It also doesn't need a complete copy of the data structure key,
    /// nor to get involved with `Isolation` edge cases.
    table: DenseSlotMap<TableIndex, ServiceState<D>>,
}

/// Entry in the 2nd-level lookup array
#[derive(Debug)]
struct IndexRecord {
    /// Client secret keys (part of the data structure key)
    secret_keys: HsClientSecretKeys,
    /// Circuit isolation (part of the data structure key)
    isolation: Box<dyn Isolation>,
    /// Index into `Services.table`, intermediate value, data structure key for next step
    table_index: TableIndex,
}

/// Value in the `Services` data structure
///
/// State and history of of our connections, including connection to any connection task.
///
/// `last_used` is used to expire data eventually.
// TODO HS actually expire old data
//
// TODO unify this with channels and circuits.  See arti#778.
#[derive(Educe)]
#[educe(Debug)]
enum ServiceState<D: MockableConnectorData> {
    /// We don't have a circuit
    Closed {
        /// The state
        data: D,
        /// Last time we touched this, including reuse
        #[allow(dead_code)] // TODO hs remove, when we do expiry
        last_used: Instant,
    },
    /// We have an open circuit, which we can (hopefully) just use
    Open {
        /// The state
        data: D,
        /// The circuit
        #[educe(Debug(ignore))]
        circuit: D::ClientCirc,
        /// Last time we touched this, including reuse
        last_used: Instant,
    },
    /// We have a task trying to find the service and establish the circuit
    ///
    /// CachedData is owned by the task.
    Working {
        /// Signals instances of `get_or_launch_connection` when the task completes
        barrier_recv: postage::barrier::Receiver,
        /// Where the task will store the error.
        ///
        /// Lock hierarchy: this lock is "inside" the big lock on `Services`.
        error: Arc<Mutex<Option<HsClientConnError>>>,
    },
    /// Dummy value for use with temporary mem replace
    Dummy,
}

impl<D: MockableConnectorData> ServiceState<D> {
    /// Make a new (blank) `ServiceState::Closed`
    fn blank(runtime: &impl Runtime) -> Self {
        ServiceState::Closed {
            data: D::default(),
            last_used: runtime.now(),
        }
    }
}

impl<D: MockableConnectorData> Services<D> {
    /// Connect to a hidden service
    // We *do* drop guard.  There is *one* await point, just after drop(guard).
    #[allow(clippy::await_holding_lock)]
    pub(crate) async fn get_or_launch_connection(
        connector: &HsClientConnector<impl Runtime, D>,
        hs_id: HsId,
        isolation: Box<dyn Isolation>,
        secret_keys: HsClientSecretKeys,
    ) -> Result<D::ClientCirc, HsClientConnError> {
        let blank_state = || ServiceState::blank(&connector.runtime);

        let mut guard = connector
            .services
            .lock()
            .map_err(|_| internal!("HS connector poisoned"))?;
        let services = &mut *guard;

        trace!("HS conn get_or_launch: {hs_id:?} {isolation:?} {secret_keys:?}");
        //trace!("HS conn services: {services:?}");

        let records = services.index.entry(hs_id).or_default();

        let table_index = match records
            .iter_mut()
            .enumerate()
            .find_map(|(v_index, record)| {
                // Deconstruct so that we can't accidentally fail to check some of the key fields
                let IndexRecord {
                    secret_keys: t_keys,
                    isolation: t_isolation,
                    table_index: _,
                } = record;
                (t_keys == &secret_keys).then(|| ())?;
                let new_isolation = t_isolation.join(&*isolation)?;
                Some((v_index, new_isolation))
            }) {
            Some((v_index, new_isolation)) => {
                records[v_index].isolation = new_isolation;
                records[v_index].table_index
            }
            None => {
                let table_index = services.table.insert(blank_state());
                records.push(IndexRecord {
                    secret_keys: secret_keys.clone(),
                    isolation,
                    table_index,
                });
                table_index
            }
        };

        for _attempt in 0..MAX_ATTEMPTS {
            let state = guard
                .table
                .get_mut(table_index)
                .ok_or_else(|| internal!("guard table entry vanished!"))?;

            trace!("HS conn state: {state:?}");

            let (data, barrier_send) = match state {
                ServiceState::Open {
                    data: _,
                    circuit,
                    last_used,
                } => {
                    let now = connector.runtime.now();
                    if !D::circuit_is_ok(circuit) {
                        // Well that's no good, we need a fresh one, but keep the data
                        let data = match mem::replace(state, ServiceState::Dummy) {
                            ServiceState::Open {
                                data,
                                last_used: _,
                                circuit: _,
                            } => data,
                            _ => panic!("state changed between maches"),
                        };
                        *state = ServiceState::Closed {
                            data,
                            last_used: now,
                        };
                        continue;
                    }
                    *last_used = now;
                    return Ok(circuit.clone());
                }
                ServiceState::Working {
                    barrier_recv,
                    error,
                } => {
                    if !matches!(
                        barrier_recv.try_recv(),
                        Err(postage::stream::TryRecvError::Pending)
                    ) {
                        // This information is stale; the task no longer exists.
                        // We want information from a fresh attempt.
                        *state = blank_state();
                        continue;
                    }
                    let mut barrier_recv = barrier_recv.clone();
                    let error = error.clone();
                    drop(guard);
                    // Wait for the task to complete (at which point it drops the barrier)
                    barrier_recv.recv().await;
                    let error = error
                        .lock()
                        .map_err(|_| internal!("Working error poisoned"))?;
                    if let Some(error) = &*error {
                        return Err(error.clone());
                    }
                    drop(error);
                    guard = connector
                        .services
                        .lock()
                        .map_err(|_| internal!("HS connector poisoned (relock)"))?;
                    continue;
                }
                ServiceState::Closed { .. } => {
                    let (barrier_send, barrier_recv) = postage::barrier::channel();
                    let data = match mem::replace(
                        state,
                        ServiceState::Working {
                            barrier_recv,
                            error: Arc::new(Mutex::new(None)),
                        },
                    ) {
                        ServiceState::Closed { data, .. } => data,
                        _ => panic!("state changed between maches"),
                    };
                    (data, barrier_send)
                }
                ServiceState::Dummy => {
                    *state = blank_state();
                    return Err(internal!("HS connector found dummy state").into());
                }
            };

            // Make a connection attempt
            let runtime = &connector.runtime;
            let connector = (*connector).clone();
            let secret_keys = secret_keys.clone();
            let connect_future = async move {
                let mut data = data;

                let got = AssertUnwindSafe(D::connect(&connector, &mut data, secret_keys))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| {
                        data = D::default();
                        Err(internal!("hidden service connector task panicked!").into())
                    });
                let last_used = connector.runtime.now();
                let got_error = got.as_ref().map(|_| ()).map_err(Clone::clone);

                // block for handling inability to store
                let stored = async {
                    // If we can't record the new state, just panic this task.
                    let mut guard = connector
                        .services
                        .lock()
                        .map_err(|_| internal!("HS connector poisoned"))?;
                    let state = guard
                        .table
                        .get_mut(table_index)
                        .ok_or_else(|| internal!("HS table entry removed while task running"))?;
                    // Always match this, so we check what we're overwriting
                    let error_store = match state {
                        ServiceState::Working { error, .. } => error,
                        _ => return Err(internal!("HS task found state other than Working")),
                    };

                    match got {
                        Ok(circuit) => {
                            *state = ServiceState::Open {
                                data,
                                circuit,
                                last_used,
                            }
                        }
                        Err(error) => {
                            let mut error_store = error_store.lock().map_err(|_| {
                                internal!("Working error poisoned, cannot store error")
                            })?;
                            *error_store = Some(error);
                        }
                    };

                    Ok(())
                }
                .await;

                match (got_error, stored) {
                    (Ok::<(), HsClientConnError>(()), Ok::<(), Bug>(())) => {}
                    (Err(got_error), Ok(())) => debug!(
                        "HS connection failure: {}",
                        // TODO HS show hs_id,
                        got_error.report(),
                    ),
                    (Ok(()), Err(bug)) => error!(
                        "internal error storing built HS circuit: {}",
                        // TODO HS show sv(hs_id),
                        bug.report(),
                    ),
                    (Err(got_error), Err(bug)) => error!(
                        "internal error storing HS connection error: {}; {}",
                        // TODO HS show sv(hs_id),
                        got_error.report(),
                        bug.report(),
                    ),
                };
                drop(barrier_send);
            };
            runtime
                .spawn_obj(Box::new(connect_future).into())
                .map_err(|cause| HsClientConnError::Spawn {
                    spawning: "connection task",
                    cause: cause.into(),
                })?;
        }

        Err(internal!("HS connector state management malfunction (exceeded MAX_ATTEMPTS").into())
    }
}

/// Mocking for actual HS connection work, to let us test the `Services` state machine
//
// Does *not* mock circmgr, chanmgr, etc. - those won't be used by the tests, since our
// `connect` won't call them.  But mocking them pollutes many types with `R` and is
// generally tiresome.  So let's not.  Instead the tests can make dummy ones.
//
// This trait is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
#[async_trait]
pub trait MockableConnectorData: Default + Debug + Send + Sync + 'static {
    /// Client circuit
    type ClientCirc: Clone + Sync + Send + 'static;

    /// Mock state
    type MockGlobalState: Clone + Sync + Send + 'static;

    /// Connect
    async fn connect<R: Runtime>(
        connector: &HsClientConnector<R, Self>,
        data: &mut Self,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Self::ClientCirc, HsClientConnError>;

    /// Is circuit OK?  Ie, not `.is_closing()`.
    fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool;
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::*;
    use futures::{poll, SinkExt};
    use std::task::Poll::{self, *};
    use tokio::pin;
    use tokio_crate as tokio;
    use tor_rtcompat::test_with_one_runtime;
    use tracing_test::traced_test;

    use HsClientConnError as E;

    #[derive(Debug, Default)]
    struct MockData {
        // things will appear here when we have more sophisticated tests
    }

    /// Type indicating what our `connect()` should return; it always makes a fresh MockCirc
    type MockGive = Poll<Result<(), E>>;

    #[derive(Debug, Clone)]
    struct MockGlobalState {
        // things will appear here when we have more sophisticated tests
        give: postage::watch::Receiver<MockGive>,
    }

    #[derive(Clone, Debug)]
    struct MockCirc {
        ok: Arc<Mutex<bool>>,
    }

    impl PartialEq for MockCirc {
        fn eq(&self, other: &MockCirc) -> bool {
            Arc::ptr_eq(&self.ok, &other.ok)
        }
    }

    impl MockCirc {
        fn new() -> Self {
            let ok = Arc::new(Mutex::new(true));
            MockCirc { ok }
        }
    }

    #[async_trait]
    impl MockableConnectorData for MockData {
        type ClientCirc = MockCirc;
        type MockGlobalState = MockGlobalState;

        async fn connect<R: Runtime>(
            connector: &HsClientConnector<R, MockData>,
            _data: &mut MockData,
            _secret_keys: HsClientSecretKeys,
        ) -> Result<Self::ClientCirc, E> {
            let make = |()| MockCirc::new();
            let mut give = connector.mock_for_state.give.clone();
            if let Ready(ret) = &*give.borrow() {
                return ret.clone().map(make);
            }
            loop {
                match give.recv().await.expect("EOF on mock_global_state stream") {
                    Pending => {}
                    Ready(ret) => return ret.map(make),
                }
            }
        }

        fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool {
            *circuit.ok.lock().unwrap()
        }
    }

    /// Makes a non-empty `HsClientSecretKeys`, containing (somehow) `kk`
    fn mk_keys(kk: u8) -> HsClientSecretKeys {
        let mut ss = [0_u8; 32];
        ss[0] = kk;
        let ss = tor_llcrypto::pk::ed25519::SecretKey::from_bytes(&ss).unwrap();
        let mut b = HsClientSecretKeysBuilder::default();
        b.ks_hsc_intro_auth(ss.into());
        b.build().unwrap()
    }

    fn mk_hsconn<R: Runtime>(
        runtime: R,
    ) -> (
        HsClientConnector<R, MockData>,
        HsClientSecretKeys,
        postage::watch::Sender<MockGive>,
    ) {
        let chanmgr = tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &Default::default(),
            tor_chanmgr::Dormancy::Dormant,
            &Default::default(),
        );
        let guardmgr = tor_guardmgr::GuardMgr::new(
            runtime.clone(),
            tor_persist::TestingStateMgr::new(),
            &tor_guardmgr::TestConfig::default(),
        )
        .unwrap();
        let circmgr = tor_circmgr::CircMgr::new(
            &tor_circmgr::TestConfig::default(),
            tor_persist::TestingStateMgr::new(),
            &runtime,
            Arc::new(chanmgr),
            guardmgr,
        )
        .unwrap();
        let netdir_provider = tor_netdir::testprovider::TestNetDirProvider::new();
        let netdir_provider = Arc::new(netdir_provider);
        let (give_send, give) = postage::watch::channel_with(Ready(Ok(())));
        let mock_for_state = MockGlobalState { give };
        #[allow(clippy::let_and_return)] // we'll probably add more in this function
        let hscc = HsClientConnector {
            runtime,
            circmgr,
            netdir_provider,
            services: Default::default(),
            mock_for_state,
        };
        let keys = HsClientSecretKeysBuilder::default().build().unwrap();
        (hscc, keys, give_send)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn mk_isol(s: &str) -> Option<NarrowableIsolation> {
        Some(NarrowableIsolation(s.into()))
    }

    async fn launch_one(
        hsconn: &HsClientConnector<impl Runtime, MockData>,
        id: u8,
        secret_keys: &HsClientSecretKeys,
        isolation: Option<NarrowableIsolation>,
    ) -> Result<MockCirc, HsClientConnError> {
        let hs_id = {
            let mut hs_id = [0_u8; 32];
            hs_id[0] = id;
            hs_id.into()
        };
        #[allow(clippy::redundant_closure)] // srsly, that would be worse
        let isolation = isolation.unwrap_or_default().into();
        Services::get_or_launch_connection(hsconn, hs_id, isolation, secret_keys.clone()).await
    }

    #[derive(Default, Debug, Clone)]
    struct NarrowableIsolation(String);
    impl tor_circmgr::isolation::IsolationHelper for NarrowableIsolation {
        fn compatible_same_type(&self, other: &Self) -> bool {
            self.join_same_type(other).is_some()
        }
        fn join_same_type(&self, other: &Self) -> Option<Self> {
            Some(if self.0.starts_with(&other.0) {
                self.clone()
            } else if other.0.starts_with(&self.0) {
                other.clone()
            } else {
                return None;
            })
        }
    }

    #[test]
    #[traced_test]
    fn simple() {
        test_with_one_runtime!(|runtime| async {
            let (hsconn, keys, _give_send) = mk_hsconn(runtime);

            let circuit = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            eprintln!("{:?}", circuit);
        });
    }

    #[test]
    #[traced_test]
    fn coalesce() {
        test_with_one_runtime!(|runtime| async {
            let (hsconn, keys, mut give_send) = mk_hsconn(runtime);

            give_send.send(Pending).await.unwrap();

            let c1f = launch_one(&hsconn, 0, &keys, None);
            pin!(c1f);
            for _ in 0..10 {
                assert!(poll!(&mut c1f).is_pending());
            }

            // c2f will find Working
            let c2f = launch_one(&hsconn, 0, &keys, None);
            pin!(c2f);
            for _ in 0..10 {
                assert!(poll!(&mut c1f).is_pending());
                assert!(poll!(&mut c2f).is_pending());
            }

            give_send.send(Ready(Ok(()))).await.unwrap();

            let c1 = c1f.await.unwrap();
            let c2 = c2f.await.unwrap();
            assert_eq!(c1, c2);

            // c2 will find Open
            let c3 = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_eq!(c1, c3);

            assert_ne!(c1, launch_one(&hsconn, 1, &keys, None).await.unwrap());
            assert_ne!(
                c1,
                launch_one(&hsconn, 0, &mk_keys(42), None).await.unwrap()
            );

            let c_isol_1 = launch_one(&hsconn, 0, &keys, mk_isol("a")).await.unwrap();
            assert_eq!(c1, c_isol_1); // We can reuse, but now we've narrowed the isol

            let c_isol_2 = launch_one(&hsconn, 0, &keys, mk_isol("b")).await.unwrap();
            assert_ne!(c1, c_isol_2);
        });
    }
}
