use chilli_core::Config;
use std::process::Command;
use tracing::{error, info};

pub struct Firewall {
    config: Config,
}

impl Firewall {
    pub fn new(config: Config) -> Self {
        Firewall { config }
    }

    pub fn initialize(&self) -> Result<(), std::io::Error> {
        info!("Initializing firewall rules");

        // Create ipset
        self.run_command("ipset", &["create", "authenticated_users", "hash:ip"])?;

        // Create chilli chains
        self.run_command("iptables", &["-t", "mangle", "-N", "chilli"])?;
        self.run_command("iptables", &["-t", "nat", "-N", "chilli"])?;
        self.run_command("iptables", &["-t", "filter", "-N", "chilli"])?;

        // Mangle table rules
        self.run_command("iptables", &["-t", "mangle", "-A", "PREROUTING", "-j", "chilli"])?;
        self.run_command("iptables", &["-t", "mangle", "-A", "chilli", "-m", "set", "--match-set", "authenticated_users", "src", "-j", "MARK", "--set-mark", "1"])?;

        // NAT table rules
        self.run_command("iptables", &["-t", "nat", "-A", "PREROUTING", "-j", "chilli"])?;
        let dnat_dest = format!("{}:{}", self.config.uamlisten, self.config.uamport);
        self.run_command("iptables", &["-t", "nat", "-A", "chilli", "-m", "mark", "!", "--mark", "1", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", &dnat_dest])?;

        // Filter table rules
        self.run_command("iptables", &["-t", "filter", "-A", "FORWARD", "-j", "chilli"])?;
        self.run_command("iptables", &["-t", "filter", "-A", "chilli", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])?;
        let uam_dest = self.config.uamlisten.to_string();
        let uam_port_str = self.config.uamport.to_string();
        self.run_command("iptables", &["-t", "filter", "-A", "chilli", "-p", "tcp", "--dport", &uam_port_str, "-d", &uam_dest, "-j", "ACCEPT"])?;
        self.run_command("iptables", &["-t", "filter", "-A", "chilli", "-m", "set", "--match-set", "authenticated_users", "src", "-j", "ACCEPT"])?;
        self.run_command("iptables", &["-t", "filter", "-A", "chilli", "-j", "DROP"])?;

        Ok(())
    }

    pub fn add_authenticated_ip(&self, ip: std::net::Ipv4Addr) -> Result<(), std::io::Error> {
        info!("Adding {} to authenticated users", ip);
        self.run_command("ipset", &["add", "authenticated_users", &ip.to_string()])
    }

    pub fn remove_authenticated_ip(&self, ip: std::net::Ipv4Addr) -> Result<(), std::io::Error> {
        info!("Removing {} from authenticated users", ip);
        self.run_command("ipset", &["del", "authenticated_users", &ip.to_string()])
    }

    pub fn apply_user_filter(&self, ip: std::net::Ipv4Addr, filter_id: &str) -> Result<(), std::io::Error> {
        let chain_name = format!("chilli-user-{}", ip);
        info!("Applying user filter for {} with chain {}", ip, chain_name);

        // Clean up any old chain first
        self.remove_user_filter(ip)?;

        // Create new chain
        self.run_command("iptables", &["-t", "filter", "-N", &chain_name])?;

        // Add jump rule from main chilli chain to user chain
        self.run_command("iptables", &["-t", "filter", "-I", "chilli", "1", "-s", &ip.to_string(), "-j", &chain_name])?;

        // Parse filter_id and add rules
        for rule in filter_id.split(';') {
            let args: Vec<&str> = rule.split_whitespace().collect();
            if !args.is_empty() {
                let mut full_args = vec!["-t", "filter", "-A", &chain_name];
                full_args.extend(args);
                self.run_command("iptables", &full_args)?;
            }
        }

        Ok(())
    }

    pub fn remove_user_filter(&self, ip: std::net::Ipv4Addr) -> Result<(), std::io::Error> {
        let chain_name = format!("chilli-user-{}", ip);
        info!("Removing user filter for {} with chain {}", ip, chain_name);

        // Remove jump rule
        self.run_command("iptables", &["-t", "filter", "-D", "chilli", "-s", &ip.to_string(), "-j", &chain_name]).ok();

        // Flush and delete user chain
        self.run_command("iptables", &["-t", "filter", "-F", &chain_name]).ok();
        self.run_command("iptables", &["-t", "filter", "-X", &chain_name]).ok();

        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), std::io::Error> {
        info!("Cleaning up firewall rules");

        // Mangle table rules
        self.run_command("iptables", &["-t", "mangle", "-D", "PREROUTING", "-j", "chilli"])?;
        self.run_command("iptables", &["-t", "mangle", "-F", "chilli"])?;
        self.run_command("iptables", &["-t", "mangle", "-X", "chilli"])?;

        // NAT table rules
        self.run_command("iptables", &["-t", "nat", "-D", "PREROUTING", "-j", "chilli"])?;
        self.run_command("iptables", &["-t", "nat", "-F", "chilli"])?;
        self.run_command("iptables", &["-t", "nat", "-X", "chilli"])?;

        // Filter table rules
        self.run_command("iptables", &["-t", "filter", "-D", "FORWARD", "-j", "chilli"])?;
        self.run_command("iptables", &["-t", "filter", "-F", "chilli"])?;
        self.run_command("iptables", &["-t", "filter", "-X", "chilli"])?;

        // Destroy ipset
        self.run_command("ipset", &["destroy", "authenticated_users"])?;

        Ok(())
    }

    fn run_command(&self, command: &str, args: &[&str]) -> Result<(), std::io::Error> {
        let status = Command::new(command).args(args).status()?;
        if !status.success() {
            let msg = format!("Command '{}' with args '{:?}' failed with status {}", command, args, status);
            error!("{}", msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }
        Ok(())
    }
}
