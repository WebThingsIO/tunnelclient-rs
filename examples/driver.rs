// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Simple driver based registration client.

extern crate env_logger;
#[macro_use]
extern crate log;
extern crate tunnelclient;

use std::env;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use tunnelclient::driver::{Driver, DriverMessage, State, start_driver};

const DEFAULT_USER: &'static str = "demo";

fn main() {
    env_logger::init().unwrap();

    // if we have a command line parameter, use it as a name to register.
    let user_name = match env::args().nth(1) {
        Some(name) => name,
        None => DEFAULT_USER.to_owned(),
    };

    info!("Starting driver for {} ...", user_name);

    let driver = Driver::from(&PathBuf::from("./config.toml"))
        .expect("Failed to create driver from config file.");

    let (tx, rx) = channel::<DriverMessage>();
    let driver_tx = start_driver(&driver, tx);

    // Trigger a State answer from the driver.
    driver_tx.send(DriverMessage::GetState).unwrap();

    loop {
        match rx.recv().unwrap() {
            DriverMessage::State(state) => {
                info!("State is {:?}", state);
                if state == State::Unsubscribed {
                    driver_tx
                        .send(DriverMessage::Subscribe(user_name.clone(),
                                                       "Test Server".to_owned()))
                        .unwrap();
                } else if state == State::NeedCertificates {
                    driver_tx.send(DriverMessage::GetCertificates).unwrap();
                }
            }

            _ => unimplemented!(),
        }
    }
}
