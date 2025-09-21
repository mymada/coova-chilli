use clap::Parser;
use chilli_core::Config;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long, value_parser, default_value = "/etc/chilli/chilli.toml")]
    pub config_file: PathBuf,
}

use std::collections::HashMap;
use tracing::{info, warn};

pub async fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let args = Args::parse();
    load_config_from_path(&args.config_file).await
}

pub async fn load_config_from_path(path: &PathBuf) -> Result<Config, Box<dyn std::error::Error>> {
    let config_contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&config_contents)?;

    if let Some(radconf_mode) = &config.radconf {
        if radconf_mode == "url" {
            if let Some(url) = &config.radconf_url {
                info!("Fetching remote configuration from URL: {}", url);
                let client = reqwest::Client::new();
                let mut request = client.get(url);

                if let (Some(user), Some(pwd)) = (&config.radconf_user, &config.radconf_pwd) {
                    info!("Using HTTP Basic Auth with user: {}", user);
                    request = request.basic_auth(user, Some(pwd));
                }

                match request.send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.text().await {
                                Ok(text) => {
                                    info!("Successfully fetched remote config.");
                                    let remote_values = parse_remote_config(&text);
                                    merge_config(&mut config, remote_values);
                                }
                                Err(e) => warn!("Failed to read remote config response text: {}", e),
                            }
                        } else {
                            warn!(
                                "Remote config URL fetch failed with status: {}",
                                response.status()
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch remote config URL: {}", e);
                    }
                }
            } else {
                warn!("radconf is 'url' but radconf_url is not set.");
            }
        }
    }

    Ok(config)
}

fn parse_remote_config(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');
            values.insert(key.to_string(), value.to_string());
        }
    }
    values
}

fn merge_config(config: &mut Config, remote_values: HashMap<String, String>) {
    for (key, value) in remote_values {
        info!("Applying remote config: {} = {}", key, value);
        match key.as_str() {
            "HS_UAMURL" => config.uamurl = Some(value),
            "HS_UAMSECRET" => config.uamsecret = Some(value),
            "HS_RADIUSSERVER1" => {
                if let Ok(ip) = value.parse() {
                    config.radiusserver1 = ip;
                } else {
                    warn!("Invalid IP address for HS_RADIUSSERVER1: {}", value);
                }
            }
            "HS_RADIUSSECRET" => config.radiussecret = value,
            "HS_DNS1" => {
                if let Ok(ip) = value.parse() {
                    config.dns1 = ip;
                } else {
                    warn!("Invalid IP address for HS_DNS1: {}", value);
                }
            }
            "HS_DNS2" => {
                if let Ok(ip) = value.parse() {
                    config.dns2 = ip;
                } else {
                    warn!("Invalid IP address for HS_DNS2: {}", value);
                }
            }
            "HS_DOMAIN" => config.domain = Some(value),
            _ => warn!("Unknown remote configuration key: {}", key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use wiremock::matchers::{method, path};
    use wiremock::{MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_remote_config_loading() {
        // Start a background mock server
        let server = MockServer::start().await;

        // Create the mock response
        let remote_body = "HS_UAMURL = \"http://remote.example.com/login\"\nHS_RADIUSSECRET = 'newsecret'";
        let response = ResponseTemplate::new(200).set_body_string(remote_body);

        // Set up the mock server to respond to GET /config
        wiremock::Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(response)
            .mount(&server)
            .await;

        // Create a temporary config file pointing to the mock server
        let mut temp_config_file = NamedTempFile::new().unwrap();
        let mut config_content = r#"
            foreground = true
            debug = true
            logfacility = 3
            loglevel = "info"
            interval = 3600
            pidfile = "/var/run/chilli.pid"
            statedir = "/var/run"
            net = "192.168.182.0"
            mask = "255.255.255.0"
            dns1 = "8.8.8.8"
            dns2 = "8.8.4.4"
            radiuslisten = "0.0.0.0"
            radiusserver1 = "127.0.0.1"
            radiussecret = "originalsecret"
            radiusauthport = 1812
            radiusacctport = 1813
            coaport = 3799
            dhcpif = "eth0"
            dhcplisten = "192.168.182.1"
            dhcpstart = "192.168.182.10"
            dhcpend = "192.168.182.254"
            lease = 3600
            uamlisten = "192.168.182.1"
            uamport = 3990
            max_clients = 1024
        "#.to_string();

        config_content.push_str(&format!(
            "\nradconf = \"url\"\nradconf_url = \"{}/config\"",
            server.uri()
        ));
        writeln!(temp_config_file, "{}", config_content).unwrap();


        // Load the config from the temporary file
        let config =
            load_config_from_path(&temp_config_file.path().to_path_buf()).await.unwrap();

        // Assert that the values have been updated
        assert_eq!(
            config.uamurl,
            Some("http://remote.example.com/login".to_string())
        );
        assert_eq!(config.radiussecret, "newsecret");
    }
}
