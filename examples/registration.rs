// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
#[macro_use]
extern crate log;
extern crate pagekite;
extern crate tunnelclient;

use pagekite::{PageKite, InitFlags, LOG_NORMAL};
use std::env;
use std::fs::File;
use std::io::Error;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tunnelclient::ip_addrs::get_ip_addr;
use tunnelclient::http_api::TunnelClient;

const HOST: &'static str = "http://knilxof.org";
const DOMAIN: &'static str = "knilxof.org";
const DEFAULT_USER: &'static str = "demo";
const TUNNEL_SECRET: &'static str = "moziot";
const TUNNEL_PORT: i32 = 4443;
const LOCAL_PORT: i32 = 4443;

fn get_saved_token() -> Result<String, Error> {
    let mut file = File::open("tunnel_token")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn main() {
    env_logger::init().unwrap();

    // if we have a command line parameter, use it as a name to register.
    let user_name = match env::args().nth(1) {
        Some(name) => name,
        None => DEFAULT_USER.to_owned(),
    };

    info!("Starting registration for {} ...", user_name);

    // Check if we can get a saved token
    let token = match get_saved_token() {
        Ok(token) => token,
        Err(_) => {
            let client = TunnelClient::new(HOST, None);
            let client = client
                .subscribe(&user_name, None)
                .expect("Failed to subscribe!");
            let token = client.token.unwrap();
            info!("New client token is {}", token);
            let mut file = File::create("tunnel_token").unwrap();
            file.write_all(token.as_bytes()).unwrap();
            token
        }
    };

    // Check if we have cert.pem and key.pem and trigger the Let's Encrypt
    // flow if not.
    if File::open("certificate.pem").is_err() || File::open("privatekey.pem").is_err() {
        let client = TunnelClient::new(HOST, Some(token.clone()));
        client
            .lets_encrypt(DOMAIN, &user_name, Path::new("."))
            .expect("Failed to complete the DNS challenge");
    } else {
        info!("We have a certificate and a key already, skipping Let's Encrypt challenge.");
    }

    let client = TunnelClient::new(HOST, Some(token.clone()));
    if let Ok(info) = client.info() {
        info!("Full record is {:?}", info);
    }

    // Register the endpoint every minute to keep our record up to date.

    let u_name = user_name.clone();
    let handle = thread::Builder::new()
        .name("registration".into())
        .spawn(move || {
            let delay = 60;
            info!("Starting registration thread, delay is {}s", delay);
            loop {
                thread::sleep(Duration::new(delay as u64, 0));
                let local_ip = get_ip_addr(&None).expect("Failed to get the local ip address!");
                let client = TunnelClient::new(HOST, Some(token.clone()));
                info!("Registering `{}.box.{}` with {}", u_name, DOMAIN, local_ip);
                // Ignore errors that could be transient.
                client.register(&local_ip).unwrap_or(());
            }
        })
        .expect("Failed to start eviction thread!");

    // Setup the PageKite tunnel.
    let pagekite = PageKite::init(Some("moziot-tunnel"),
                                  1, // max kites: just one for https.
                                  1, // max frontends
                                  10, // max connections.
                                  None, // dyndns url
                                  &[InitFlags::WithIpv4, InitFlags::WithIpv6],
                                  &LOG_NORMAL)
            .expect("Failed to create PageKite object!");
    pagekite.lookup_and_add_frontend(DOMAIN, TUNNEL_PORT, true);
    pagekite.add_kite("https",
                      &format!("{}.box.{}", user_name, DOMAIN),
                      TUNNEL_PORT,
                      TUNNEL_SECRET,
                      "localhost",
                      LOCAL_PORT);
    pagekite.thread_start();

    handle.join().unwrap();
}
