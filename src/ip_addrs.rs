// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use get_if_addrs::{self, IfAddr, Interface};

fn get_ip_addr_from_ifaces(ifaces: &[Interface], want_iface: &Option<String>) -> Option<String> {

    let mut ip_addr: Option<String> = None;
    let mut ipv6_addr: Option<String> = None;

    for iface in ifaces {
        match want_iface.as_ref() {
                None =>
                    // Whitelist known good iface
                    if !(iface.name.starts_with("eth") ||
                         iface.name.starts_with("wlan") ||
                         iface.name.starts_with("en") ||
                         iface.name.starts_with("em") ||
                         iface.name.starts_with("wlp3s") ||
                         iface.name.starts_with("wlp4s")) {
                        continue;
                    },
                    Some(iface_name) =>
                        if &iface.name != iface_name {
                            continue;
                        }
            }
        if let IfAddr::V4(ref v4) = iface.addr {
            ip_addr = Some(format!("{}", v4.ip));
            break;
        } else if ipv6_addr.is_none() {
            if let IfAddr::V6(ref v6) = iface.addr {
                ipv6_addr = Some(format!("{}", v6.ip));
            }
        }
    }

    if ip_addr.is_none() {
        if ipv6_addr.is_none() {
            error!("No IP interfaces found!");
        } else {
            ip_addr = ipv6_addr;
        }
    }
    ip_addr
}

/// return the host IP address of the first valid interface.
/// `want_iface` is an options string for the interface you want.
pub fn get_ip_addr(want_iface: &Option<String>) -> Option<String> {
    // Look for an ipv4 interface on eth* or wlan*.
    if let Ok(ifaces) = get_if_addrs::get_if_addrs() {
        if ifaces.is_empty() {
            error!("No IP interfaces found!");
            return None;
        }

        get_ip_addr_from_ifaces(&ifaces, want_iface)
    } else {
        error!("No IP interfaces found!");
        None
    }
}
