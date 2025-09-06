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

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config_contents = fs::read_to_string(args.config_file)?;

    // This is a placeholder. In a real implementation, you would use a library
    // like `toml` to parse the config file and then merge it with command-line
    // arguments. For now, we'll just return a default config.

    let config: Config = toml::from_str(&config_contents)?;

    Ok(config)
}
