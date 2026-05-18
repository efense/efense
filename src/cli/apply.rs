// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    ffi::CString,
    path::Path,
};

use aya::{
    maps::{
        Array, HashMap as AyaHashMap, MapData,
        lpm_trie::{Key as LpmKey, LpmTrie as AyaLpmTrie},
        of_maps::HashOfMaps as AyaHashOfMaps,
    },
    programs::{
        Xdp, XdpMode,
        links::{FdLink, PinnedLink},
    },
};
use efence::{
    Action, EfenceConfig, EfenceError, Interface, Ipv4CidrPod, PrefixPortPod,
    Tcp4IngressRule, TcpIngressPolicy, Udp4IngressRule, UdpIngressPolicy,
};
use efence_core::{
    ACTION_DROP, ACTION_PASS, CFG_BLOB_LEN, Ipv4Cidr, MAP_CFG, MAP_CFG_LEN,
    MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION, MAP_TCP_INGRESS_IFACE_TO_LPM,
    MAP_TCP_INGRESS_PORT_ACTION, MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION,
    MAP_UDP_INGRESS_IFACE_TO_LPM, MAP_UDP_INGRESS_PORT_ACTION, MAX_PREFIXES,
    PORT_ANY, PrefixPort,
};
use log::debug;

use crate::pin::{
    ensure_pin_dirs, link_pin_path, main_map_pin_path, program_pin_path,
    tcp_ingress_map_pin_path, udp_ingress_map_pin_path,
};

const ARG_CONFIG: &str = "CONFIG";
const PROG_NAME: &str = "efence_net_ingress_apply";

/// `BPF_F_NO_PREALLOC` flag value (1). The kernel forces this on for
/// LPM tries, but we set it explicitly so the inner LPM template we
/// create from userspace matches the BTF-declared inner template.
const BPF_F_NO_PREALLOC: u32 = 1;

pub(crate) struct CommandApply;

impl CommandApply {
    pub(crate) const CMD: &str = "apply";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("Load efense configuration into the kernel")
            .arg(clap::Arg::new(ARG_CONFIG).required(true).help(
                "Path to the YAML configuration file, or '-' to read YAML \
                 from stdin",
            ))
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), EfenceError> {
        let source: &String = matches
            .get_one::<String>(ARG_CONFIG)
            .expect("clap required CONFIG");
        let cfg = if source == "-" {
            load_config_from_stdin()?
        } else {
            load_config_from_file(Path::new(source))?
        };
        apply(cfg)?;
        Ok(())
    }
}

fn load_config_from_file(path: &Path) -> Result<EfenceConfig, EfenceError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        EfenceError::from(format!(
            "failed to read config {}: {e}",
            path.display()
        ))
    })?;
    parse_config(&text)
}

fn load_config_from_stdin() -> Result<EfenceConfig, EfenceError> {
    use std::io::Read;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(|e| {
        EfenceError::from(format!("failed to read config from stdin: {e}"))
    })?;
    parse_config(&text)
}

fn parse_config(text: &str) -> Result<EfenceConfig, EfenceError> {
    serde_yaml::from_str::<EfenceConfig>(text).map_err(|e| {
        EfenceError::from(format!("failed to parse YAML config: {e}"))
    })
}

fn apply(mut cfg: EfenceConfig) -> Result<(), EfenceError> {
    bump_memlock();
    ensure_pin_dirs()?;

    // Merge any previously-applied config back in so a partial apply
    // does not implicitly drop unrelated interfaces. We probe for the
    // pinned `CFG_LEN` map specifically: a stale pin *directory* with no
    // maps inside (e.g. left over from a failed apply or from a previous
    // schema) must be treated as "no prior config", not as an error.
    if main_map_pin_path(MAP_CFG_LEN).exists() {
        let current = crate::show::read_config()?;
        cfg.merge(&current);
    }

    let mut ebpf = load_ebpf_program()?;

    populate_maps(&mut ebpf, &cfg)?;
    pin_maps(&mut ebpf)?;

    load_and_pin_program(&mut ebpf)?;
    attach_and_pin_links(&mut ebpf, &cfg)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Map population
// ---------------------------------------------------------------------------

fn populate_maps(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenceConfig,
) -> Result<(), EfenceError> {
    // Compute the flattened rule set per interface, indexed by ifindex.
    let udp_by_iface = collect_udp_per_iface(cfg)?;
    let tcp_by_iface = collect_tcp_per_iface(cfg)?;

    populate_udp_iface_default_action(ebpf, &udp_by_iface)?;
    populate_udp_iface_to_lpm(ebpf, &udp_by_iface)?;
    populate_udp_port_action(ebpf, &udp_by_iface)?;

    populate_tcp_iface_default_action(ebpf, &tcp_by_iface)?;
    populate_tcp_iface_to_lpm(ebpf, &tcp_by_iface)?;
    populate_tcp_port_action(ebpf, &tcp_by_iface)?;

    write_cfg_blob(ebpf, cfg)?;

    Ok(())
}

/// Per-interface materialized policy: default action + the rules
/// expanded into `(canonical prefix, port-or-ANY, action)` triples.
struct IfacePolicy {
    default_action: Action,
    /// All canonical prefixes appearing on this interface, deduplicated.
    prefixes: HashSet<Ipv4Cidr>,
    /// Triples (canonical prefix, port or `PORT_ANY`, action).
    port_rules: Vec<(Ipv4Cidr, u16, Action)>,
}

fn collect_udp_per_iface(
    cfg: &EfenceConfig,
) -> Result<StdHashMap<u32, IfacePolicy>, EfenceError> {
    let mut by_iface: StdHashMap<u32, IfacePolicy> = StdHashMap::new();
    for iface in &cfg.interfaces {
        let UdpIngressPolicy {
            default_action,
            allow_list,
        } = match iface.udp_ingress.as_ref() {
            Some(p) => p,
            None => continue,
        };

        let ifindex = lookup_ifindex(&iface.name)?;
        let entry = by_iface.entry(ifindex).or_insert(IfacePolicy {
            default_action: *default_action,
            prefixes: HashSet::new(),
            port_rules: Vec::new(),
        });
        entry.default_action = *default_action;

        for rule in allow_list {
            expand_udp_rule(rule, entry)?;
        }
    }
    Ok(by_iface)
}

fn collect_tcp_per_iface(
    cfg: &EfenceConfig,
) -> Result<StdHashMap<u32, IfacePolicy>, EfenceError> {
    let mut by_iface: StdHashMap<u32, IfacePolicy> = StdHashMap::new();
    for iface in &cfg.interfaces {
        let TcpIngressPolicy {
            default_action,
            allow_list,
        } = match iface.tcp_ingress.as_ref() {
            Some(p) => p,
            None => continue,
        };

        let ifindex = lookup_ifindex(&iface.name)?;
        let entry = by_iface.entry(ifindex).or_insert(IfacePolicy {
            default_action: *default_action,
            prefixes: HashSet::new(),
            port_rules: Vec::new(),
        });
        entry.default_action = *default_action;

        for rule in allow_list {
            expand_tcp_rule(rule, entry)?;
        }
    }
    Ok(by_iface)
}

fn expand_udp_rule(
    rule: &Udp4IngressRule,
    out: &mut IfacePolicy,
) -> Result<(), EfenceError> {
    let prefix = udp_rule_prefix(rule);
    out.prefixes.insert(prefix);

    let action = match out.default_action {
        Action::Drop => Action::Pass,
        Action::Pass => Action::Drop,
    };

    let port = rule.src_port.unwrap_or(PORT_ANY);
    out.port_rules.push((prefix, port, action));
    Ok(())
}

fn expand_tcp_rule(
    rule: &Tcp4IngressRule,
    out: &mut IfacePolicy,
) -> Result<(), EfenceError> {
    let prefix = tcp_rule_prefix(rule);
    out.prefixes.insert(prefix);

    let action = match out.default_action {
        Action::Drop => Action::Pass,
        Action::Pass => Action::Drop,
    };

    let port = rule.dst_port.unwrap_or(PORT_ANY);
    out.port_rules.push((prefix, port, action));
    Ok(())
}

fn udp_rule_prefix(rule: &Udp4IngressRule) -> Ipv4Cidr {
    match rule.src_ip {
        Some(cidr) => Ipv4Cidr::new(cidr.addr.octets(), cidr.prefix_len),
        None => Ipv4Cidr::any(),
    }
}

fn tcp_rule_prefix(rule: &Tcp4IngressRule) -> Ipv4Cidr {
    match rule.src_ip {
        Some(cidr) => Ipv4Cidr::new(cidr.addr.octets(), cidr.prefix_len),
        None => Ipv4Cidr::any(),
    }
}

fn lookup_ifindex(name: &str) -> Result<u32, EfenceError> {
    let cname = CString::new(name).map_err(|e| {
        EfenceError::from(format!("interface name {name:?}: {e}"))
    })?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        let err = std::io::Error::last_os_error();
        return Err(EfenceError::from(format!(
            "if_nametoindex({name:?}) failed: {err}"
        )));
    }
    Ok(idx)
}

fn populate_udp_iface_default_action(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf
        .map_mut(MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION)
        .ok_or_else(|| {
            EfenceError::from(format!(
                "{MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION} map not found"
            ))
        })?;
    let mut hm: AyaHashMap<&mut MapData, u32, u32> = AyaHashMap::try_from(map)?;
    for (ifindex, policy) in by_iface {
        hm.insert(ifindex, action_value(policy.default_action), 0)?;
    }
    Ok(())
}

fn populate_tcp_iface_default_action(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf
        .map_mut(MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION)
        .ok_or_else(|| {
            EfenceError::from(format!(
                "{MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION} map not found"
            ))
        })?;
    let mut hm: AyaHashMap<&mut MapData, u32, u32> = AyaHashMap::try_from(map)?;
    for (ifindex, policy) in by_iface {
        hm.insert(ifindex, action_value(policy.default_action), 0)?;
    }
    Ok(())
}

fn populate_udp_iface_to_lpm(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf.map_mut(MAP_UDP_INGRESS_IFACE_TO_LPM).ok_or_else(|| {
        EfenceError::from(format!(
            "{MAP_UDP_INGRESS_IFACE_TO_LPM} map not found"
        ))
    })?;
    let mut outer: AyaHashOfMaps<
        &mut MapData,
        u32,
        AyaLpmTrie<MapData, [u8; 4], Ipv4CidrPod>,
    > = AyaHashOfMaps::try_from(map)?;

    for (ifindex, policy) in by_iface {
        let mut inner = AyaLpmTrie::<MapData, [u8; 4], Ipv4CidrPod>::create(
            MAX_PREFIXES,
            BPF_F_NO_PREALLOC,
        )?;
        for prefix in &policy.prefixes {
            let key = LpmKey::new(prefix.prefix_len as u32, prefix.addr);
            inner.insert(&key, Ipv4CidrPod(*prefix), 0)?;
        }
        outer.insert(ifindex, &inner, 0)?;
    }
    Ok(())
}

fn populate_tcp_iface_to_lpm(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf.map_mut(MAP_TCP_INGRESS_IFACE_TO_LPM).ok_or_else(|| {
        EfenceError::from(format!(
            "{MAP_TCP_INGRESS_IFACE_TO_LPM} map not found"
        ))
    })?;
    let mut outer: AyaHashOfMaps<
        &mut MapData,
        u32,
        AyaLpmTrie<MapData, [u8; 4], Ipv4CidrPod>,
    > = AyaHashOfMaps::try_from(map)?;

    for (ifindex, policy) in by_iface {
        let mut inner = AyaLpmTrie::<MapData, [u8; 4], Ipv4CidrPod>::create(
            MAX_PREFIXES,
            BPF_F_NO_PREALLOC,
        )?;
        for prefix in &policy.prefixes {
            let key = LpmKey::new(prefix.prefix_len as u32, prefix.addr);
            inner.insert(&key, Ipv4CidrPod(*prefix), 0)?;
        }
        outer.insert(ifindex, &inner, 0)?;
    }
    Ok(())
}

fn populate_udp_port_action(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf.map_mut(MAP_UDP_INGRESS_PORT_ACTION).ok_or_else(|| {
        EfenceError::from(format!(
            "{MAP_UDP_INGRESS_PORT_ACTION} map not found"
        ))
    })?;
    let mut hm: AyaHashMap<&mut MapData, PrefixPortPod, u32> =
        AyaHashMap::try_from(map)?;

    for policy in by_iface.values() {
        for (prefix, port, action) in &policy.port_rules {
            let key = PrefixPortPod(PrefixPort::new(*prefix, *port));
            hm.insert(key, action_value(*action), 0)?;
        }
    }
    Ok(())
}

fn populate_tcp_port_action(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenceError> {
    let map = ebpf.map_mut(MAP_TCP_INGRESS_PORT_ACTION).ok_or_else(|| {
        EfenceError::from(format!(
            "{MAP_TCP_INGRESS_PORT_ACTION} map not found"
        ))
    })?;
    let mut hm: AyaHashMap<&mut MapData, PrefixPortPod, u32> =
        AyaHashMap::try_from(map)?;

    for policy in by_iface.values() {
        for (prefix, port, action) in &policy.port_rules {
            let key = PrefixPortPod(PrefixPort::new(*prefix, *port));
            hm.insert(key, action_value(*action), 0)?;
        }
    }
    Ok(())
}

fn write_cfg_blob(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenceConfig,
) -> Result<(), EfenceError> {
    let json = serde_json::to_vec(cfg).map_err(|e| {
        EfenceError::from(format!("failed to serialize config as JSON: {e}"))
    })?;
    if json.len() > CFG_BLOB_LEN {
        return Err(EfenceError::from(format!(
            "serialized config is {} bytes, exceeds max {}",
            json.len(),
            CFG_BLOB_LEN
        )));
    }

    {
        let mut cfg_map: Array<&mut MapData, u8> =
            map_array_mut(ebpf, MAP_CFG)?;
        for (i, b) in json.iter().enumerate() {
            cfg_map.set(i as u32, *b, 0)?;
        }
        // Zero out the rest so a stale tail can't surprise a reader that
        // ignores the length.
        for i in json.len()..CFG_BLOB_LEN {
            cfg_map.set(i as u32, 0u8, 0)?;
        }
    }

    {
        let mut len_map: Array<&mut MapData, u32> =
            map_array_mut(ebpf, MAP_CFG_LEN)?;
        len_map.set(0, json.len() as u32, 0)?;
    }

    Ok(())
}

fn bump_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn load_ebpf_program() -> Result<aya::Ebpf, EfenceError> {
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/efence_ebpf_cli"
    )))?)
}

fn action_value(action: Action) -> u32 {
    match action {
        Action::Pass => ACTION_PASS,
        Action::Drop => ACTION_DROP,
    }
}

fn map_array_mut<'a, V: aya::Pod>(
    ebpf: &'a mut aya::Ebpf,
    name: &str,
) -> Result<Array<&'a mut MapData, V>, EfenceError> {
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| EfenceError::from(format!("{name} map not found")))?;
    Ok(Array::try_from(map)?)
}

// ---------------------------------------------------------------------------
// Pinning & program attach
// ---------------------------------------------------------------------------

fn pin_maps(ebpf: &mut aya::Ebpf) -> Result<(), EfenceError> {
    // Maps under the UDP-ingress pin root.
    let udp_ingress_maps = [
        MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_UDP_INGRESS_IFACE_TO_LPM,
        MAP_UDP_INGRESS_PORT_ACTION,
    ];
    // Maps under the TCP-ingress pin root.
    let tcp_ingress_maps = [
        MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_TCP_INGRESS_IFACE_TO_LPM,
        MAP_TCP_INGRESS_PORT_ACTION,
    ];
    // Maps under the shared main pin root.
    let main_maps = [MAP_CFG, MAP_CFG_LEN];

    for name in udp_ingress_maps {
        pin_one_map(ebpf, name, udp_ingress_map_pin_path(name))?;
    }
    for name in tcp_ingress_maps {
        pin_one_map(ebpf, name, tcp_ingress_map_pin_path(name))?;
    }
    for name in main_maps {
        pin_one_map(ebpf, name, main_map_pin_path(name))?;
    }
    Ok(())
}

fn pin_one_map(
    ebpf: &mut aya::Ebpf,
    name: &str,
    path: std::path::PathBuf,
) -> Result<(), EfenceError> {
    // Remove a stale pin (e.g. from a previous run) so that the
    // BPF_OBJ_PIN syscall does not fail with EEXIST.
    let _ = std::fs::remove_file(&path);
    let map = ebpf
        .map(name)
        .ok_or_else(|| EfenceError::from(format!("{name} map not found")))?;
    map.pin(&path)?;
    Ok(())
}

fn load_and_pin_program(ebpf: &mut aya::Ebpf) -> Result<(), EfenceError> {
    let program: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| {
            EfenceError::from(format!("{PROG_NAME} program not found"))
        })?
        .try_into()?;
    program.load()?;

    let pin_path = program_pin_path();
    let _ = std::fs::remove_file(&pin_path);
    program.pin(&pin_path)?;

    Ok(())
}

fn attach_and_pin_links(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenceConfig,
) -> Result<(), EfenceError> {
    let program: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| {
            EfenceError::from(format!("{PROG_NAME} program not found"))
        })?
        .try_into()?;

    for iface in interfaces_with_policy(cfg) {
        attach_and_pin_link(program, iface)?;
    }
    Ok(())
}

fn interfaces_with_policy(cfg: &EfenceConfig) -> Vec<&Interface> {
    cfg.interfaces
        .iter()
        .filter(|i| i.udp_ingress.is_some() || i.tcp_ingress.is_some())
        .collect()
}

fn attach_and_pin_link(
    program: &mut Xdp,
    iface: &Interface,
) -> Result<(), EfenceError> {
    let pin_path = link_pin_path(&iface.name);

    // Detach any previous pinned link for this interface first so a
    // re-apply is idempotent.
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

    let link_id = program.attach(&iface.name, XdpMode::default())?;
    let link = program.take_link(link_id)?;
    let fd_link: FdLink = link.try_into()?;
    let _pinned: PinnedLink = fd_link.pin(&pin_path)?;
    eprintln!("Attached and pinned XDP link for {}", iface.name);
    Ok(())
}
