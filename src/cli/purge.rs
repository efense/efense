// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use aya::programs::links::PinnedLink;
use efense::EfenseError;
use log::warn;

use crate::pin::{
    PIN_MAIN_DIR, PIN_TCP_INGRESS_DIR, PIN_UDP_INGRESS_DIR, link_pin_dir,
};

pub(crate) struct CommandPurge;

impl CommandPurge {
    pub(crate) const CMD: &str = "purge";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("Remove all eBPF programs, maps and links pinned by `apply`")
    }

    pub(crate) async fn handle(
        _matches: &clap::ArgMatches,
    ) -> Result<(), EfenseError> {
        let roots = [
            Path::new(PIN_UDP_INGRESS_DIR),
            Path::new(PIN_TCP_INGRESS_DIR),
            Path::new(PIN_MAIN_DIR),
        ];
        if roots.iter().all(|p| !p.exists()) {
            eprintln!("No efense configuration is loaded; nothing to purge.");
            return Ok(());
        }

        // Detach links first while the link pin dir is still live; this
        // depends on `PIN_UDP_INGRESS_DIR` so it must run before we
        // remove that tree.
        detach_links()?;

        for root in roots {
            if root.exists() {
                remove_tree(root)?;
                eprintln!("Removed {}", root.display());
            }
        }
        Ok(())
    }
}

/// Open every pinned link and unpin it so the kernel detaches the XDP
/// program from the corresponding interface.
fn detach_links() -> Result<(), EfenseError> {
    let dir = link_pin_dir();
    if !dir.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(&dir).map_err(|e| {
        EfenseError::from(format!(
            "failed to read link pin dir {}: {e}",
            dir.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            EfenseError::from(format!("failed to iterate link pin dir: {e}"))
        })?;
        let path = entry.path();
        match PinnedLink::from_pin(&path) {
            Ok(pinned) => {
                if let Err(e) = pinned.unpin() {
                    warn!("failed to unpin link {}: {e}", path.display());
                    let _ = std::fs::remove_file(&path);
                }
            }
            Err(e) => {
                warn!("failed to open pinned link {}: {e}", path.display());
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(())
}

fn remove_tree(path: &Path) -> Result<(), EfenseError> {
    std::fs::remove_dir_all(path).map_err(|e| {
        EfenseError::from(format!(
            "failed to remove pin tree {}: {e}",
            path.display()
        ))
    })
}
