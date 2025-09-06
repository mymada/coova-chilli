use chilli_core::Config;
use tun_tap::{Iface, Mode};

/// Creates and configures a new TUN interface.
///
/// # Arguments
///
/// * `config` - A reference to the application configuration.
///
/// # Returns
///
/// A `Result` containing the new `Iface` instance, or a `tun_tap::Error` if an
/// error occurred.
pub fn create_tun(config: &Config) -> Result<Iface, tun_tap::Error> {
    let iface = Iface::new("", Mode::Tun)?;

    if let Some(tundev) = &config.tundev {
        iface.set_name(tundev)?;
    }

    iface.set_ip(config.net)?;
    iface.set_netmask(config.mask)?;

    iface.up()?;

    Ok(iface)
}
