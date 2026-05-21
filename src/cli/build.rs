// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, io};

use aya_build::Toolchain;

fn main() -> Result<(), Box<dyn Error>> {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new().no_deps().exec()?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| {
            name.as_str() == "efense_ebpf"
        })
        .ok_or_else(|| io::Error::other("efense_ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| {
                io::Error::other(format!("no parent for {manifest_path}"))
            })?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;
    Ok(())
}
