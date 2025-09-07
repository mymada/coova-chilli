use anyhow::Result;
use chilli_core::Config;
use tun_rs::{DeviceBuilder, AsyncDevice};

/// Creates and configures a new TUN interface.
///
/// # Arguments
///
/// * `config` - A reference to the application configuration.
///
/// # Returns
///
/// A `Result` containing the new `AsyncDevice` instance.
pub async fn create_tun(config: &Config) -> Result<AsyncDevice> {
    let mut builder = DeviceBuilder::new()
        .name(config.tundev.as_deref().unwrap_or("tun0").to_string())
        .mtu(1500); // A standard MTU

    let mask_prefix = u32::from(config.mask).leading_ones();
    builder = builder.ipv4(config.net, mask_prefix as u8, None);

    let dev = builder.build_async()?;

    Ok(dev)
}
