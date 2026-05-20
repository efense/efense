// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Borrow,
    path::{Path, PathBuf},
};

use aya::{
    maps::{Array as AyaArray, Map, MapData, RingBuf},
    programs::{
        Xdp, XdpMode,
        links::{FdLink, PinnedLink},
    },
};
use aya_log::EbpfLogger;
use efence::{EfenceError, EfenceEvent, ErrorKind, Tcp4Event, Udp4Event};
use efence_core::{
    MAP_MONITOR_ENABLED, MAP_TCP4_EVENTS, MAP_UDP4_EVENTS, Tcp4EventRaw,
    Udp4EventRaw,
};
use log::warn;
use tokio::{io::Interest, signal};

use crate::{
    apply,
    pin::{
        PIN_MAIN_DIR, ensure_pin_dirs, link_pin_path, main_map_pin_path,
        program_pin_path,
    },
};

const ARG_IFACE: &str = "IFACE";

pub(crate) struct CommandMonitor;

impl CommandMonitor {
    pub(crate) const CMD: &str = "monitor";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about(
                "Monitor network events (stops automatically if event queue \
                 is full)",
            )
            .arg(
                clap::Arg::new(ARG_IFACE)
                    .short('i')
                    .long("iface")
                    .required(true)
                    .help("Interface to attach XDP program to"),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), EfenceError> {
        let iface = matches
            .get_one::<String>(ARG_IFACE)
            .expect("clap required IFACE");

        if !Path::new(PIN_MAIN_DIR).exists() {
            setup_bpf_state(iface)?;
        }

        let udp_ring_buf =
            open_pinned_ring_buf(main_map_pin_path(MAP_UDP4_EVENTS))?;
        let tcp_ring_buf =
            open_pinned_ring_buf(main_map_pin_path(MAP_TCP4_EVENTS))?;

        set_monitor_enabled(true)?;

        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();

        spawn_udp4_task(udp_ring_buf, ev_tx.clone());
        spawn_tcp4_task(tcp_ring_buf, ev_tx);
        spawn_event_printer(ev_rx);

        let ctrl_c = signal::ctrl_c();
        eprintln!("Waiting for Ctrl-C...");
        ctrl_c.await?;
        eprintln!("Exiting...");

        set_monitor_enabled(false)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Standalone setup (when `efctl apply` has not been run)
// ---------------------------------------------------------------------------

fn setup_bpf_state(iface: &str) -> Result<(), EfenceError> {
    apply::bump_memlock();
    ensure_pin_dirs()?;
    let mut ebpf = apply::load_ebpf_program()?;

    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Pin the monitor maps so the pinned-ring-buf path below can open them.
    let main_maps = [MAP_UDP4_EVENTS, MAP_TCP4_EVENTS, MAP_MONITOR_ENABLED];
    for name in main_maps {
        apply::pin_one_map(&mut ebpf, name, main_map_pin_path(name))?;
    }

    // Load and pin the XDP program.
    let program: &mut Xdp = ebpf
        .program_mut(apply::PROG_NAME)
        .ok_or_else(|| {
            EfenceError::from(format!("{} program not found", apply::PROG_NAME))
        })?
        .try_into()?;
    program.load()?;

    let pin_path = program_pin_path();
    let _ = std::fs::remove_file(&pin_path);
    program.pin(&pin_path)?;

    // Attach to the interface and pin the link so it survives this process.
    let pin_path = link_pin_path(iface);
    if pin_path.exists() {
        match PinnedLink::from_pin(&pin_path) {
            Ok(pinned) => {
                let _ = pinned.unpin();
            }
            Err(_) => {
                let _ = std::fs::remove_file(&pin_path);
            }
        }
    }
    let link_id = program.attach(iface, XdpMode::default())?;
    let link = program.take_link(link_id)?;
    let fd_link: FdLink = link.try_into()?;
    let _pinned: PinnedLink = fd_link.pin(&pin_path)?;
    eprintln!("Attached and pinned XDP link for {iface}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Pinned-map helpers
// ---------------------------------------------------------------------------

fn open_pinned_ring_buf(
    path: PathBuf,
) -> Result<RingBuf<MapData>, EfenceError> {
    let map_data = MapData::from_pin(&path).map_err(|e| EfenceError {
        kind: ErrorKind::Map,
        msg: format!("failed to open {path:?}: {e}"),
    })?;
    let map = Map::from_map_data(map_data)?;
    Ok(RingBuf::try_from(map)?)
}

fn set_monitor_enabled(enabled: bool) -> Result<(), EfenceError> {
    let path = main_map_pin_path(MAP_MONITOR_ENABLED);
    if !enabled && !path.exists() {
        return Ok(());
    }
    let map_data = MapData::from_pin(&path).map_err(|e| EfenceError {
        kind: ErrorKind::Map,
        msg: format!("failed to open MONITOR_ENABLED map at {path:?}: {e}"),
    })?;
    let map = Map::from_map_data(map_data)?;
    let mut arr: AyaArray<MapData, u32> = AyaArray::try_from(map)?;
    let value: u32 = if enabled { 1 } else { 0 };
    arr.set(0, value, 0)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Event polling
// ---------------------------------------------------------------------------

fn spawn_udp4_task(
    ring_buf: RingBuf<impl Borrow<MapData> + Send + 'static>,
    tx: tokio::sync::mpsc::UnboundedSender<EfenceEvent>,
) {
    let mut events =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, Interest::READABLE)
            .expect("Failed to create AsyncFd for UDP4 ring buffer");
    tokio::task::spawn(async move {
        loop {
            let mut guard = events.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                match Udp4EventRaw::parse(&item) {
                    Ok(raw) => {
                        let event = Udp4Event::from(raw);
                        let _ = tx.send(EfenceEvent::Udp4Ingress(event));
                    }
                    Err(e) => warn!("failed to parse UDP4 event: {e}"),
                }
            }
            guard.clear_ready();
        }
    });
}

fn spawn_tcp4_task(
    ring_buf: RingBuf<impl Borrow<MapData> + Send + 'static>,
    tx: tokio::sync::mpsc::UnboundedSender<EfenceEvent>,
) {
    let mut events =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, Interest::READABLE)
            .expect("Failed to create AsyncFd for TCP4 ring buffer");
    tokio::task::spawn(async move {
        loop {
            let mut guard = events.readable_mut().await.unwrap();
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                match Tcp4EventRaw::parse(&item) {
                    Ok(raw) => {
                        let event = Tcp4Event::from(raw);
                        let _ = tx.send(EfenceEvent::Tcp4Ingress(event));
                    }
                    Err(e) => warn!("failed to parse TCP4 event: {e}"),
                }
            }
            guard.clear_ready();
        }
    });
}

fn spawn_event_printer(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<EfenceEvent>,
) {
    tokio::task::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Ok(s) = serde_yaml::to_string(&[ev]) {
                print!("{s}");
            }
        }
    });
}
