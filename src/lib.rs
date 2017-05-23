// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate acme_client;
#[macro_use]
extern crate log;
extern crate registration_server;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate url;

use acme_client::Directory;
use acme_client::error::Error as AcmeError;
use registration_server::api_types::NameAndToken;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};
use reqwest::{Client, StatusCode};

pub struct TunnelClient {
    pub tunnel_url: String,
    pub token: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug)]
pub enum TunnelClientError {
    NoName,
    NoToken,
    NoChallenge,
    BadRequest,
    Other(String),
    Acme(AcmeError),
}

fn url_param(param: &str) -> String {
    percent_encode(param.as_bytes(), QUERY_ENCODE_SET).collect::<String>()
}

impl std::convert::From<AcmeError> for TunnelClientError {
    fn from(err: AcmeError) -> Self {
        TunnelClientError::Acme(err)
    }
}

impl std::convert::From<reqwest::Error> for TunnelClientError {
    fn from(err: reqwest::Error) -> Self {
        TunnelClientError::Other(format!("{}", err))
    }
}

impl TunnelClient {
    pub fn new(tunnel_url: &str, token: Option<String>, name: Option<String>) -> Self {
        TunnelClient {
            tunnel_url: tunnel_url.to_owned(),
            token: token,
            name: name,
        }
    }

    // Triggers a subscription.
    pub fn subscribe(&self, name: &str, description: Option<&str>) -> Option<Self> {
        let client = Client::new().expect("Client creation failure");
        let mut url: String = format!("{}/subscribe?name={}", self.tunnel_url, url_param(name));
        if let Some(desc) = description {
            url.push_str(&format!("&desc={}", url_param(desc)));
        }

        match client.get(&url).send() {
            // If the status is 200, the response is {"name": "xxx", "token": "yyy"}
            Ok(mut response) => {
                if *response.status() == StatusCode::Ok {
                    let data: Result<NameAndToken, reqwest::Error> = response.json();
                    match data {
                        Ok(n_t) => {
                            Some(TunnelClient {
                                     tunnel_url: self.tunnel_url.clone(),
                                     token: Some(n_t.token),
                                     name: Some(n_t.name),
                                 })
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    // Renew the registration with a given local ip.
    // Will return false if this failed for any reason.
    pub fn register(&self, local_ip: &str) -> Result<(), TunnelClientError> {
        match self.token {
            Some(ref token) => {
                let client = Client::new().expect("Client creation failure");
                match client
                          .get(&format!("{}/register?token={}&local_ip={}",
                                        self.tunnel_url,
                                        url_param(token),
                                        url_param(local_ip)))
                          .send() {
                    Ok(response) => {
                        if *response.status() == StatusCode::Ok {
                            Ok(())
                        } else {
                            Err(TunnelClientError::BadRequest)
                        }
                    }
                    Err(err) => Err(TunnelClientError::from(err)),
                }
            }
            None => {
                error!("No token available to register {}", local_ip);
                Err(TunnelClientError::NoToken)
            }
        }
    }

    // Starts the LE workflow.
    pub fn lets_encrypt(&self, domain: &str) -> Result<(), TunnelClientError> {
        let name = if let Some(ref name) = self.name {
            name
        } else {
            error!("Can't run lets_encrypt without a name");
            return Err(TunnelClientError::NoName);
        };

        if let Some(ref token) = self.token {

            let directory = Directory::lets_encrypt()?;
            let account = directory.account_registration().register()?;

            let remote_domain = format!("{}.box.{}", name, domain);
            let local_domain = format!("local.{}.box.{}", name, domain);

            let domains = [remote_domain.as_str(), local_domain.as_str()];

            for domain in domains.iter() {
                let authorization = account.authorization(&domain)?;
                let dns_challenge = match authorization.get_dns_challenge() {
                    Some(challenge) => challenge,
                    None => return Err(TunnelClientError::NoChallenge),
                };
                let signature = dns_challenge.signature()?;

                let client = Client::new().expect("Client creation failure");
                client
                    .get(&format!("{}/dnsconfig?token={}&challenge={}",
                                  self.tunnel_url,
                                  url_param(token),
                                  url_param(&signature)))
                    .send()?;

                dns_challenge.validate()?;
                info!("DNS challenge validated for {}", domain);
            }

            let certificate_signer = account.certificate_signer(&domains);
            let cert = certificate_signer.sign_certificate()?;
            cert.save_signed_certificate_and_chain(None, "certificate.pem")?;
            cert.save_private_key("privatekey.pem")?;
            info!("Certificate and private key for {} saved.", domain);
            return Ok(());
        } else {
            error!("No token available to retrieve the certificate for {}",
                   domain);
            return Err(TunnelClientError::NoToken);
        }
    }
}
