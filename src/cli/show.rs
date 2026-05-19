// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use aya::maps::{Array, Map, MapData};
use efence::{EfenceConfig, EfenceError, ErrorKind};
use efence_core::{CFG_BLOB_LEN, MAP_CFG, MAP_CFG_LEN};

use crate::pin::{PIN_MAIN_DIR, main_map_pin_path};

pub(crate) struct CommandShow;

impl CommandShow {
    pub(crate) const CMD: &str = "show";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD).about(
            "Show the efense configuration currently loaded in the kernel",
        )
    }

    pub(crate) async fn handle(
        _matches: &clap::ArgMatches,
    ) -> Result<(), EfenceError> {
        let cfg = if Path::new(PIN_MAIN_DIR).exists() {
            read_config()?
        } else {
            EfenceConfig {
                interfaces: Vec::new(),
            }
        };
        let yaml = serde_yaml::to_string(&cfg).map_err(|e| {
            EfenceError::from(format!("failed to serialize config: {e}"))
        })?;
        print!("{yaml}");
        Ok(())
    }
}

/// Read the [`EfenceConfig`] that `efctl apply` previously serialized
/// into the pinned `CFG` byte-array map.
pub(crate) fn read_config() -> Result<EfenceConfig, EfenceError> {
    let len_path = main_map_pin_path(MAP_CFG_LEN);
    if !len_path.exists() {
        return Ok(EfenceConfig {
            interfaces: Vec::new(),
        });
    }
    let len_map: Array<MapData, u32> = open_pinned_array(MAP_CFG_LEN)?;
    let len = len_map.get(&0, 0)? as usize;
    if len == 0 {
        return Ok(EfenceConfig {
            interfaces: Vec::new(),
        });
    }
    if len > CFG_BLOB_LEN {
        return Err(EfenceError::from(format!(
            "stored config length {len} exceeds max {CFG_BLOB_LEN}"
        )));
    }

    let blob: Array<MapData, u8> = open_pinned_array(MAP_CFG)?;
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len as u32 {
        bytes.push(blob.get(&i, 0)?);
    }

    serde_json::from_slice::<EfenceConfig>(&bytes).map_err(|e| {
        EfenceError::from(format!(
            "failed to deserialize stored config JSON: {e}"
        ))
    })
}

fn open_pinned_array<V: aya::Pod>(
    name: &str,
) -> Result<Array<MapData, V>, EfenceError> {
    let path = main_map_pin_path(name);
    let data = MapData::from_pin(&path).map_err(|e| EfenceError {
        kind: ErrorKind::Map,
        msg: format!("failed to open pinned map {}: {e}", path.display()),
    })?;
    let map = Map::from_map_data(data)?;
    Ok(Array::try_from(map)?)
}
