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
use efense::{
    Action, EfenseConfig, EfenseError, Interface, Ipv4CidrPod, PortKeyPod,
    PrefixPortPod, Tcp4IngressRule, TcpIngressPolicy, Udp4IngressRule,
    UdpIngressPolicy,
};
use efense_core::{
    ACTION_DROP, ACTION_PASS, ALLOW_OUTGOING_FLAG, CFG_BLOB_LEN, Ipv4Cidr,
    MAP_CFG, MAP_CFG_LEN, MAP_MONITOR_ENABLED, MAP_PORT_ALLOW_LIST,
    MAP_PROTO_DFLT, MAP_TCP_ACK_FLOOD_PROTECTION_ENABLED,
    MAP_TCP_ACK_ISN_TRACKER, MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION,
    MAP_TCP_INGRESS_IFACE_TO_LPM, MAP_TCP_INGRESS_PORT_ACTION, MAP_TCP4_EVENTS,
    MAP_UDP_INGRESS_IFACE_TO_LPM, MAP_UDP_INGRESS_PORT_ACTION, MAP_UDP4_EVENTS,
    MAX_PREFIXES, PORT_ANY, PROTO_DFLT_TCP, PROTO_DFLT_UDP, PortKey,
    PrefixPort,
};
use log::debug;

use crate::pin::{
    ensure_pin_dirs, link_pin_path, main_map_pin_path, program_pin_path,
    tcp_ingress_map_pin_path, udp_ingress_map_pin_path,
};

const ARG_CONFIG: &str = "CONFIG";
pub(crate) const PROG_NAME: &str = "efense_net_xdp_ingress_apply";

/// `BPF_F_NO_PREALLOC` flag value (1). The kernel forces this on for
/// LPM tries, but we set it explicitly so the inner LPM template we
/// create from userspace matches the BTF-declared inner template.
const BPF_F_NO_PREALLOC: u32 = 1;

pub(crate) struct CommandApply;

impl CommandApply {
    pub(crate) const CMD: &str = "apply";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new(Self::CMD)
            .alias("a")
            .about("Load efense configuration into the kernel")
            .arg(clap::Arg::new(ARG_CONFIG).required(true).help(
                "Path to the YAML configuration file, or '-' to read YAML \
                 from stdin",
            ))
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), EfenseError> {
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

fn load_config_from_file(path: &Path) -> Result<EfenseConfig, EfenseError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        EfenseError::from(format!(
            "failed to read config {}: {e}",
            path.display()
        ))
    })?;
    parse_config(&text)
}

fn load_config_from_stdin() -> Result<EfenseConfig, EfenseError> {
    use std::io::Read;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(|e| {
        EfenseError::from(format!("failed to read config from stdin: {e}"))
    })?;
    parse_config(&text)
}

fn parse_config(text: &str) -> Result<EfenseConfig, EfenseError> {
    serde_yaml::from_str::<EfenseConfig>(text).map_err(|e| {
        EfenseError::from(format!("failed to parse YAML config: {e}"))
    })
}

fn apply(mut cfg: EfenseConfig) -> Result<(), EfenseError> {
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

    if cfg
        .interfaces
        .iter()
        .any(|i| i.tcp.as_ref().is_some_and(|t| t.protections.tcp_ack_flood))
    {
        log::warn!(
            "all prior TCP connection will be terminated, e.g. ssh need \
             relogin"
        );
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
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    // Compute the flattened rule set per interface, indexed by ifindex.
    let udp_by_iface = collect_udp_per_iface(cfg)?;
    let tcp_by_iface = collect_tcp_per_iface(cfg)?;

    populate_udp_iface_to_lpm(ebpf, &udp_by_iface)?;
    populate_udp_port_action(ebpf, &udp_by_iface)?;

    populate_tcp_iface_default_action(ebpf, &tcp_by_iface)?;
    populate_tcp_iface_to_lpm(ebpf, &tcp_by_iface)?;
    populate_tcp_port_action(ebpf, &tcp_by_iface)?;

    populate_proto_dflt(ebpf, cfg)?;

    populate_tcp_ack_flood_protection(ebpf, cfg)?;

    populate_port_allow_list(ebpf, cfg)?;

    write_cfg_blob(ebpf, cfg)?;

    Ok(())
}

/// Per-interface materialized policy: default action + the rules
/// expanded into `(canonical prefix, port-or-ANY, action)` triples.
struct IfacePolicy {
    default_action: Action,
    /// When `true`, non-SYN TCP packets are passed unconditionally.
    allow_outgoing: bool,
    /// All canonical prefixes appearing on this interface, deduplicated.
    prefixes: HashSet<Ipv4Cidr>,
    /// Triples (canonical prefix, port or `PORT_ANY`, action).
    port_rules: Vec<(Ipv4Cidr, u16, Action)>,
}

fn collect_udp_per_iface(
    cfg: &EfenseConfig,
) -> Result<StdHashMap<u32, IfacePolicy>, EfenseError> {
    let mut by_iface: StdHashMap<u32, IfacePolicy> = StdHashMap::new();
    for iface in &cfg.interfaces {
        let UdpIngressPolicy { allow_list } = match iface.udp.as_ref() {
            Some(p) => p,
            None => continue,
        };

        let ifindex = lookup_ifindex(&iface.name)?;
        let entry = by_iface.entry(ifindex).or_insert(IfacePolicy {
            default_action: Action::Drop,
            allow_outgoing: false,
            prefixes: HashSet::new(),
            port_rules: Vec::new(),
        });

        for rule in allow_list {
            expand_udp_rule(rule, entry)?;
        }
    }
    Ok(by_iface)
}

fn collect_tcp_per_iface(
    cfg: &EfenseConfig,
) -> Result<StdHashMap<u32, IfacePolicy>, EfenseError> {
    let mut by_iface: StdHashMap<u32, IfacePolicy> = StdHashMap::new();
    for iface in &cfg.interfaces {
        let TcpIngressPolicy {
            allow_list,
            allow_outgoing,
            ..
        } = match iface.tcp.as_ref() {
            Some(p) => p,
            None => continue,
        };

        let ifindex = lookup_ifindex(&iface.name)?;
        let entry = by_iface.entry(ifindex).or_insert(IfacePolicy {
            default_action: Action::Drop,
            allow_outgoing: *allow_outgoing,
            prefixes: HashSet::new(),
            port_rules: Vec::new(),
        });
        entry.allow_outgoing = *allow_outgoing;

        for rule in allow_list {
            expand_tcp_rule(rule, entry)?;
        }
    }
    Ok(by_iface)
}

fn expand_udp_rule(
    rule: &Udp4IngressRule,
    out: &mut IfacePolicy,
) -> Result<(), EfenseError> {
    let action = match out.default_action {
        Action::Drop => Action::Pass,
        Action::Pass => Action::Drop,
    };

    let port = rule.src_port.unwrap_or(PORT_ANY);

    if rule.src_ip_ranges.is_empty() {
        let prefix = Ipv4Cidr::any();
        out.prefixes.insert(prefix);
        out.port_rules.push((prefix, port, action));
    } else {
        for range_str in &rule.src_ip_ranges {
            let cidr = efense::Ipv4Cidr::parse(range_str).map_err(|e| {
                EfenseError::from(format!(
                    "invalid src_ip_range {range_str:?} in rule '{}': {e}",
                    rule.name
                ))
            })?;
            let prefix = Ipv4Cidr::new(cidr.addr.octets(), cidr.prefix_len);
            out.prefixes.insert(prefix);
            out.port_rules.push((prefix, port, action));
        }
    }
    Ok(())
}

fn expand_tcp_rule(
    rule: &Tcp4IngressRule,
    out: &mut IfacePolicy,
) -> Result<(), EfenseError> {
    let action = match out.default_action {
        Action::Drop => Action::Pass,
        Action::Pass => Action::Drop,
    };

    let port = rule.port;

    if rule.src_ip_ranges.is_empty() {
        let prefix = Ipv4Cidr::any();
        out.prefixes.insert(prefix);
        out.port_rules.push((prefix, port, action));
    } else {
        for range_str in &rule.src_ip_ranges {
            let cidr = efense::Ipv4Cidr::parse(range_str).map_err(|e| {
                EfenseError::from(format!(
                    "invalid src_ip_range {range_str:?} in rule '{}': {e}",
                    rule.name
                ))
            })?;
            let prefix = Ipv4Cidr::new(cidr.addr.octets(), cidr.prefix_len);
            out.prefixes.insert(prefix);
            out.port_rules.push((prefix, port, action));
        }
    }
    Ok(())
}

fn lookup_ifindex(name: &str) -> Result<u32, EfenseError> {
    let cname = CString::new(name).map_err(|e| {
        EfenseError::from(format!("interface name {name:?}: {e}"))
    })?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        let err = std::io::Error::last_os_error();
        return Err(EfenseError::from(format!(
            "if_nametoindex({name:?}) failed: {err}"
        )));
    }
    Ok(idx)
}

fn populate_tcp_iface_default_action(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenseError> {
    let map = ebpf
        .map_mut(MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION)
        .ok_or_else(|| {
            EfenseError::from(format!(
                "{MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION} map not found"
            ))
        })?;
    let mut hm: AyaHashMap<&mut MapData, u32, u32> = AyaHashMap::try_from(map)?;
    for (ifindex, policy) in by_iface {
        let v = if policy.allow_outgoing {
            ALLOW_OUTGOING_FLAG
        } else {
            0
        };
        hm.insert(ifindex, v, 0)?;
    }
    Ok(())
}

fn populate_udp_iface_to_lpm(
    ebpf: &mut aya::Ebpf,
    by_iface: &StdHashMap<u32, IfacePolicy>,
) -> Result<(), EfenseError> {
    let map = ebpf.map_mut(MAP_UDP_INGRESS_IFACE_TO_LPM).ok_or_else(|| {
        EfenseError::from(format!(
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
) -> Result<(), EfenseError> {
    let map = ebpf.map_mut(MAP_TCP_INGRESS_IFACE_TO_LPM).ok_or_else(|| {
        EfenseError::from(format!(
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
) -> Result<(), EfenseError> {
    let map = ebpf.map_mut(MAP_UDP_INGRESS_PORT_ACTION).ok_or_else(|| {
        EfenseError::from(format!(
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
) -> Result<(), EfenseError> {
    let map = ebpf.map_mut(MAP_TCP_INGRESS_PORT_ACTION).ok_or_else(|| {
        EfenseError::from(format!(
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

fn populate_tcp_ack_flood_protection(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    let map = ebpf
        .map_mut(MAP_TCP_ACK_FLOOD_PROTECTION_ENABLED)
        .ok_or_else(|| {
            EfenseError::from(format!(
                "{MAP_TCP_ACK_FLOOD_PROTECTION_ENABLED} map not found"
            ))
        })?;
    let mut hm: AyaHashMap<&mut MapData, u32, u32> = AyaHashMap::try_from(map)?;

    for iface in &cfg.interfaces {
        let enabled = iface
            .tcp
            .as_ref()
            .is_some_and(|t| t.protections.tcp_ack_flood);
        if enabled {
            let ifindex = lookup_ifindex(&iface.name)?;
            hm.insert(ifindex, 1u32, 0)?;
        }
    }
    Ok(())
}

fn populate_proto_dflt(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    let mut arr: Array<&mut MapData, u32> =
        map_array_mut(ebpf, MAP_PROTO_DFLT)?;

    let udp_defined = cfg.interfaces.iter().any(|i| i.udp.is_some());
    arr.set(
        PROTO_DFLT_UDP,
        if udp_defined {
            ACTION_DROP
        } else {
            ACTION_PASS
        },
        0,
    )?;

    let tcp_defined = cfg.interfaces.iter().any(|i| i.tcp.is_some());
    arr.set(
        PROTO_DFLT_TCP,
        if tcp_defined {
            ACTION_DROP
        } else {
            ACTION_PASS
        },
        0,
    )?;

    Ok(())
}

fn populate_port_allow_list(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    let map = ebpf.map_mut(MAP_PORT_ALLOW_LIST).ok_or_else(|| {
        EfenseError::from(format!("{MAP_PORT_ALLOW_LIST} map not found"))
    })?;
    let mut hm: AyaHashMap<&mut MapData, PortKeyPod, u32> =
        AyaHashMap::try_from(map)?;

    for iface in &cfg.interfaces {
        let ifindex = lookup_ifindex(&iface.name)?;

        // TCP ports.
        if let Some(tcp) = &iface.tcp {
            for rule in &tcp.allow_list {
                let key = PortKeyPod(PortKey::new(ifindex, rule.port));
                hm.insert(key, 1u32, 0)?;
            }
        }

        // UDP ports.
        if let Some(udp) = &iface.udp {
            for rule in &udp.allow_list {
                if let Some(port) = rule.src_port {
                    let key = PortKeyPod(PortKey::new(ifindex, port));
                    hm.insert(key, 1u32, 0)?;
                }
            }
        }
    }
    Ok(())
}

fn write_cfg_blob(
    ebpf: &mut aya::Ebpf,
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    let json = serde_json::to_vec(cfg).map_err(|e| {
        EfenseError::from(format!("failed to serialize config as JSON: {e}"))
    })?;
    if json.len() > CFG_BLOB_LEN {
        return Err(EfenseError::from(format!(
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

pub(crate) fn bump_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

pub(crate) fn load_ebpf_program() -> Result<aya::Ebpf, EfenseError> {
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/efense_ebpf_cli"
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
) -> Result<Array<&'a mut MapData, V>, EfenseError> {
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| EfenseError::from(format!("{name} map not found")))?;
    Ok(Array::try_from(map)?)
}

// ---------------------------------------------------------------------------
// Pinning & program attach
// ---------------------------------------------------------------------------

fn pin_maps(ebpf: &mut aya::Ebpf) -> Result<(), EfenseError> {
    // Maps under the UDP-ingress pin root.
    let udp_ingress_maps =
        [MAP_UDP_INGRESS_IFACE_TO_LPM, MAP_UDP_INGRESS_PORT_ACTION];
    // Maps under the TCP-ingress pin root.
    let tcp_ingress_maps = [
        MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_TCP_INGRESS_IFACE_TO_LPM,
        MAP_TCP_INGRESS_PORT_ACTION,
        MAP_TCP_ACK_FLOOD_PROTECTION_ENABLED,
        MAP_TCP_ACK_ISN_TRACKER,
    ];
    // Maps under the shared main pin root.
    let main_maps = [
        MAP_CFG,
        MAP_CFG_LEN,
        MAP_PORT_ALLOW_LIST,
        MAP_PROTO_DFLT,
        MAP_UDP4_EVENTS,
        MAP_TCP4_EVENTS,
        MAP_MONITOR_ENABLED,
    ];

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

pub(crate) fn pin_one_map(
    ebpf: &mut aya::Ebpf,
    name: &str,
    path: std::path::PathBuf,
) -> Result<(), EfenseError> {
    // Remove a stale pin (e.g. from a previous run) so that the
    // BPF_OBJ_PIN syscall does not fail with EEXIST.
    let _ = std::fs::remove_file(&path);
    let map = ebpf
        .map(name)
        .ok_or_else(|| EfenseError::from(format!("{name} map not found")))?;
    map.pin(&path)?;
    Ok(())
}

fn load_and_pin_program(ebpf: &mut aya::Ebpf) -> Result<(), EfenseError> {
    let program: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| {
            EfenseError::from(format!("{PROG_NAME} program not found"))
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
    cfg: &EfenseConfig,
) -> Result<(), EfenseError> {
    let program: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| {
            EfenseError::from(format!("{PROG_NAME} program not found"))
        })?
        .try_into()?;

    for iface in interfaces_with_policy(cfg) {
        attach_and_pin_link(program, iface)?;
    }
    Ok(())
}

fn interfaces_with_policy(cfg: &EfenseConfig) -> Vec<&Interface> {
    cfg.interfaces
        .iter()
        .filter(|i| {
            i.udp.is_some()
                || i.tcp.is_some()
                || i.tcp.as_ref().is_some_and(|t| t.protections.tcp_ack_flood)
        })
        .collect()
}

fn attach_and_pin_link(
    program: &mut Xdp,
    iface: &Interface,
) -> Result<(), EfenseError> {
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
