// SPDX-License-Identifier: Apache-2.0

//! Filesystem layout for pinning the efense eBPF objects.
//!
//! There are three pin roots:
//!
//! * [`PIN_MAIN_DIR`] holds maps that are *shared* across all efense subsystems
//!   (currently the serialized [`CFG`] JSON blob and its length). Keeping these
//!   out of any one subsystem's directory means that future subsystems can
//!   attach to the same shared state without ordering or cleanup coupling to
//!   the UDP-ingress subsystem.
//!
//! * [`PIN_UDP_INGRESS_DIR`] holds everything that is specific to the
//!   UDP-ingress XDP program: the program itself, its private maps and one
//!   pinned link per attached interface.
//!
//! * [`PIN_TCP_INGRESS_DIR`] holds everything that is specific to the
//!   TCP-ingress XDP program: the program itself, its private maps and one
//!   pinned link per attached interface.
//!
//! ```text
//! /sys/fs/bpf/efence_main/
//!     map/
//!         CFG
//!         CFG_LEN
//! /sys/fs/bpf/efence_udp_ingress/
//!     program
//!     map/
//!         UDP_IN_IFACE_DFLT
//!         UDP_IN_IF2LPM
//!         UDP_IN_PORT_ACT
//!     link/<iface>
//! /sys/fs/bpf/efence_tcp_ingress/
//!     program
//!     map/
//!         TCP_IN_IFACE_DFLT
//!         TCP_IN_IF2LPM
//!         TCP_IN_PORT_ACT
//!     link/<iface>
//! ```

use std::path::{Path, PathBuf};

use efence::EfenceError;

/// Pin root for state shared across efense subsystems.
pub(crate) const PIN_MAIN_DIR: &str = "/sys/fs/bpf/efence_main";

/// Pin root for the UDP-ingress XDP subsystem.
pub(crate) const PIN_UDP_INGRESS_DIR: &str = "/sys/fs/bpf/efence_udp_ingress";

/// Pin root for the TCP-ingress XDP subsystem.
pub(crate) const PIN_TCP_INGRESS_DIR: &str = "/sys/fs/bpf/efence_tcp_ingress";

const PIN_PROG_NAME: &str = "program";
const PIN_MAP_SUBDIR: &str = "map";
const PIN_LINK_SUBDIR: &str = "link";

/// Returns the pin path for the UDP apply XDP program.
pub(crate) fn program_pin_path() -> PathBuf {
    Path::new(PIN_UDP_INGRESS_DIR).join(PIN_PROG_NAME)
}

/// Returns the directory used to pin UDP-ingress private maps.
pub(crate) fn udp_ingress_map_pin_dir() -> PathBuf {
    Path::new(PIN_UDP_INGRESS_DIR).join(PIN_MAP_SUBDIR)
}

/// Returns the pin path for a single UDP-ingress private map.
pub(crate) fn udp_ingress_map_pin_path(name: &str) -> PathBuf {
    udp_ingress_map_pin_dir().join(name)
}

/// Returns the directory used to pin TCP-ingress private maps.
pub(crate) fn tcp_ingress_map_pin_dir() -> PathBuf {
    Path::new(PIN_TCP_INGRESS_DIR).join(PIN_MAP_SUBDIR)
}

/// Returns the pin path for a single TCP-ingress private map.
pub(crate) fn tcp_ingress_map_pin_path(name: &str) -> PathBuf {
    tcp_ingress_map_pin_dir().join(name)
}

/// Returns the directory used to pin shared (main) maps.
pub(crate) fn main_map_pin_dir() -> PathBuf {
    Path::new(PIN_MAIN_DIR).join(PIN_MAP_SUBDIR)
}

/// Returns the pin path for a single shared (main) map.
pub(crate) fn main_map_pin_path(name: &str) -> PathBuf {
    main_map_pin_dir().join(name)
}

/// Returns the directory used to pin per-interface XDP links.
pub(crate) fn link_pin_dir() -> PathBuf {
    Path::new(PIN_UDP_INGRESS_DIR).join(PIN_LINK_SUBDIR)
}

/// Returns the pin path for the XDP link of `iface`.
pub(crate) fn link_pin_path(iface: &str) -> PathBuf {
    link_pin_dir().join(iface)
}

/// Ensure every pin directory used by `apply` exists.
pub(crate) fn ensure_pin_dirs() -> Result<(), EfenceError> {
    for dir in [
        Path::new(PIN_MAIN_DIR).to_path_buf(),
        main_map_pin_dir(),
        Path::new(PIN_UDP_INGRESS_DIR).to_path_buf(),
        udp_ingress_map_pin_dir(),
        link_pin_dir(),
        Path::new(PIN_TCP_INGRESS_DIR).to_path_buf(),
        tcp_ingress_map_pin_dir(),
    ] {
        std::fs::create_dir_all(&dir).map_err(|e| {
            EfenceError::from(format!(
                "failed to create pin directory {}: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}
