// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The driver manages the whole lifecycle of a tunneling client.

use http_api::TunnelClient;
use ip_addrs::get_ip_addr;
use pagekite::{PageKite, InitFlags, LOG_NORMAL};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use toml;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum State {
    Unsubscribed,
    NeedCertificates,
    Ready,
    Paused,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    domain: String,
    tunnel_port: i32,
    local_port: i32,
    tunnel_secret: String,
    api_endpoint: String,
    registration_delay: u64,
    data_dir: String,
}

impl Config {
    pub fn data_dir(&self) -> PathBuf {
        PathBuf::from(&self.data_dir)
    }
}

#[derive(Clone)]
pub struct Driver {
    state: State,
    data: Data,
    config: Config,
    pagekite: Option<PageKite>,
}

error_chain! {
    foreign_links {
        Parse(toml::de::Error);
        Serialize(toml::ser::Error);
        Io(::std::io::Error);
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Data {
    token: Option<String>,
    name: Option<String>,
    renew_cert_at: Option<u64>,
}

impl Data {
    // Loads a data file from a path, or return an empty one.
    fn load(path: &PathBuf) -> Self {
        macro_rules! d {
            ($what:expr) => (
                match $what {
                    Ok(res) => res,
                    Err(_) => return Data { token: None, name: None, renew_cert_at: None }
                }
            )
        }

        let mut file = d!(File::open(path));
        let mut source = String::new();
        d!(file.read_to_string(&mut source));

        d!(toml::from_str(&source))
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        let toml = toml::to_string(&self)?;
        let mut file = File::create(path)?;
        file.write_all(toml.as_bytes())
            .chain_err(|| "Failed to write data.toml")
    }
}

impl Driver {
    // Creates a Driver, loading the configuration from the specified
    // configuration path.
    pub fn from(config_path: &PathBuf) -> Result<Self> {
        let mut file = File::open(config_path)?;
        let mut source = String::new();
        file.read_to_string(&mut source)?;

        Ok(Driver::from_config(&toml::from_str(&source)?))
    }

    pub fn from_config(config: &Config) -> Self {
        // Initial state depends on whether we have the tunnel token and
        // certificates available.
        // The tunnel token and certificates renewal time are stored in
        // a data.toml file under data_dir. The private key and chained
        // certificate are stored in the same directory.
        let root_path = Path::new(&config.data_dir);
        let data = Data::load(&root_path.join("data.toml"));

        if data.token.is_none() {
            return Driver {
                       state: State::Unsubscribed,
                       config: config.clone(),
                       data: data.clone(),
                       pagekite: None,
                   };
        }

        // We have a token, check if we have pem files.
        let have_pems = File::open(&root_path.join("privatekey.pem")).is_ok() &&
                        File::open(&root_path.join("certificate.pem")).is_ok();

        let state = if have_pems {
            State::Ready
        } else {
            State::NeedCertificates
        };

        Driver {
            state: state,
            config: config.clone(),
            data: data.clone(),
            pagekite: None,
        }
    }

    fn set_state(&mut self, state: State) {
        self.state = state;
    }

    fn set_data(&mut self, data: Data) {
        self.data = data;
    }

    fn start_pagekite(&mut self) {
        let pagekite = PageKite::init(Some("tunnel"),
                                      1, // max kites: just one for https.
                                      1, // max frontends
                                      100, // max connections.
                                      None, // dyndns url
                                      &[InitFlags::WithIpv4, InitFlags::WithIpv6],
                                      &LOG_NORMAL)
                .expect("Failed to create PageKite object!");
        pagekite.lookup_and_add_frontend(&self.config.domain, self.config.tunnel_port, true);
        pagekite.add_kite("https",
                          &format!("{}.box.{}",
                                  self.data.clone().name.unwrap(),
                                  self.config.domain),
                          self.config.tunnel_port,
                          &self.config.tunnel_secret,
                          "localhost",
                          self.config.local_port);
        pagekite.thread_start();
        self.pagekite = Some(pagekite);
    }

    fn stop_pagekite(&mut self) {
        if let Some(ref kite) = self.pagekite {
            kite.thread_stop();
        }
    }

    pub fn save_data(&self) -> Result<()> {
        let root_path = Path::new(&self.config.data_dir);
        self.data.save(&root_path.join("data.toml"))
    }

    pub fn get_client(&self) -> TunnelClient {
        TunnelClient::new(&self.config.api_endpoint, self.data.token.clone())
    }
}

pub enum DriverMessage {
    // Responses
    State(State),

    // Commands
    GetState,
    Subscribe(String, String), // (name, description)
    Unsubscribe,
    GetCertificates,
    UpdateRegistration,
    Pause,
    Resume,
    Stop,
}

// Process a message by checking the current state and triggering the appropriate action.
// TODO: move to a job queue running on its own thread.
// Returns `true` if we need to shutdown the driver.
pub fn process_message(driver: &mut Driver,
                       message: &DriverMessage,
                       sink: &Sender<DriverMessage>) -> bool {
    match *message {
        DriverMessage::GetState => {
            sink.send(DriverMessage::State(driver.state.clone()))
                .expect("Failed to send message");
        }
        DriverMessage::Subscribe(ref name, ref desc) => {
            // If our state is not `Unsubscribed` bail out.
            // TODO: return some error instead.
            if driver.state != State::Unsubscribed {
                return false;
            }

            if let Some(client) = driver.get_client().subscribe(name, Some(desc)) {
                driver.set_state(State::NeedCertificates);
                sink.send(DriverMessage::State(State::NeedCertificates))
                    .expect("Failed to send message");
                // Update the `token` and `name` properties in data and persist it.
                driver.set_data(Data {
                                    name: Some(name.to_owned()),
                                    token: client.token,
                                    renew_cert_at: None,
                                });
                if driver.save_data().is_err() {
                    // TODO: better error reporting.
                    error!("Failed to save data file!");
                }
            }

        }
        DriverMessage::Unsubscribe => {
            // If our state is `Unsubscribed` bail out.
            // TODO: return some error instead.
            if driver.state == State::Unsubscribed {
                return false;
            }

            let start_state = driver.state.clone();

            if driver.get_client().unsubscribe().is_ok() {
                driver.set_state(State::Unsubscribed);
                sink.send(DriverMessage::State(State::Unsubscribed))
                    .expect("Failed to send message");
            }

            // Stop PageKite if it was running.
            if start_state == State::Ready {
                driver.stop_pagekite();
            }

        }
        DriverMessage::GetCertificates => {
            // If our state is not `NeedCertificates` bail out.
            // TODO: return some error instead.
            if driver.state != State::NeedCertificates {
                return false;
            }

            if driver
                   .get_client()
                   .lets_encrypt(&driver.config.domain,
                                 &driver.data.name.clone().unwrap(),
                                 &driver.config.data_dir())
                   .is_ok() {
                driver.set_state(State::Ready);
                sink.send(DriverMessage::State(State::Ready))
                    .expect("Failed to send message");
                // Update the `renew_cert_at` property in data and persist it.
                let name = driver.data.name.clone();
                let token = driver.data.token.clone();
                // While LE certificates are valid for 3 months, it is recommended
                // to renew at 2/3 of their lifetime (60 days).
                // See https://letsencrypt.org/docs/integration-guide/
                let renewal_date = SystemTime::now() + Duration::new(60 * 24 * 3600, 0);
                driver.set_data(Data {
                                    name: name,
                                    token: token,
                                    renew_cert_at: Some(renewal_date
                                                            .duration_since(UNIX_EPOCH)
                                                            .unwrap()
                                                            .as_secs()),
                                });
                if driver.save_data().is_err() {
                    // TODO: better error reporting.
                    error!("Failed to save data file!");
                }

                // Start the PageKite tunnel as well.
                driver.start_pagekite();
            }

        }
        DriverMessage::UpdateRegistration => {
            // Only registers if we are in the `Ready` state.
            if driver.state != State::Ready {
                return false;
            }

            let local_ip = get_ip_addr(&None).expect("Failed to get the local ip address!");
            let name = driver.data.name.clone().unwrap();
            info!("Registering {} with {}", name, local_ip);
            // Ignore errors that could be transient.
            driver.get_client().register(&local_ip).unwrap_or(());
        }
        DriverMessage::Pause => {
            if driver.state != State::Ready {
                return false;
            }

            driver.stop_pagekite();

            driver.set_state(State::Paused);
                sink.send(DriverMessage::State(State::Paused))
                    .expect("Failed to send message");
        }
        DriverMessage::Resume => {
            if driver.state != State::Paused {
                return false;
            }

            driver.start_pagekite();

            driver.set_state(State::Ready);
                sink.send(DriverMessage::State(State::Ready))
                    .expect("Failed to send message");
        }
        DriverMessage::Stop => {
            if driver.state == State::Ready {
                driver.stop_pagekite();
            }

            return true;
        }
        _ => unimplemented!(),
    }

    false
}

// Registers at regular intervals.
fn start_registration(interval: u64, target: Sender<DriverMessage>) {

    thread::Builder::new()
        .name("registration thread".to_owned())
        .spawn(move || {
                   info!("Starting registration thread, interval is {}s", interval);
                   loop {
                       target.send(DriverMessage::UpdateRegistration).unwrap();
                       thread::sleep(Duration::new(interval, 0));
                   }
               })
        .expect("Failed to start tunnel driver thread");
}

// Starts the driver, and returns a communication channel to send commands.
pub fn start_driver(driver: &Driver, sink: Sender<DriverMessage>) -> Sender<DriverMessage> {
    let mut driver = driver.clone();
    let delay = driver.config.registration_delay;

    let (tx, rx) = channel::<DriverMessage>();

    let tx2 = tx.clone();

    thread::Builder::new()
        .name(format!("tunnel driver for {}", driver.config.domain))
        .spawn(move || {
            info!("Starting driver");

            // Starts the PageKite tunnel right away if we are in a `Ready` state.
            if driver.state == State::Ready {
                start_registration(delay, tx2);
                driver.start_pagekite();
            }

            let mut iter = rx.iter();
            loop {
                match iter.next() {
                    Some(message) => {
                        if process_message(&mut driver, &message, &sink) {
                            break;
                        }
                    }
                    None => {
                        info!("Exiting driver thread!");
                        break;
                    }
                }
            }
            info!("Stopping driver");
        })
        .expect("Failed to start tunnel driver thread");

    tx
}
