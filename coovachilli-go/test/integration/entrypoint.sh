#!/bin/bash
set -e

echo "=== CoovaChilli-Go Integration Test Container ==="
echo "Firewall Backend: ${FIREWALL_BACKEND:-auto}"

# Load kernel modules required for networking
modprobe tun 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
modprobe ip6table_nat 2>/dev/null || true
modprobe xt_MASQUERADE 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Configure firewall backend
if [ "${FIREWALL_BACKEND}" = "ufw" ]; then
    echo "Configuring UFW..."
    # Enable UFW
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 8080/tcp
    ufw allow 67/udp
    ufw allow 547/udp
    CONFIG_FILE="/app/config.ufw.yaml"
elif [ "${FIREWALL_BACKEND}" = "iptables" ]; then
    echo "Configuring iptables..."
    CONFIG_FILE="/app/config.iptables.yaml"
else
    echo "Auto-detecting firewall backend..."
    CONFIG_FILE="/app/config.yaml"
fi

# Use the appropriate config file
if [ -f "${CONFIG_FILE}" ]; then
    ln -sf "${CONFIG_FILE}" /app/config.yaml
fi

echo "Network configuration:"
ip addr show
echo ""
echo "IPv6 status:"
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
echo ""
echo "Starting CoovaChilli-Go with config: ${CONFIG_FILE}"

# Wait a bit for network to be ready
sleep 2

# Execute the main command
exec "$@"
