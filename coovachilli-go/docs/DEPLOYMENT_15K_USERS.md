# Déploiement Multi-Serveurs pour 15,000 Utilisateurs

## Architecture Globale

```
                                    Internet
                                       |
                                   Firewall
                                       |
                        +---------------------------+
                        |    Load Balancer (HAProxy)|
                        |    10.0.0.10              |
                        +---------------------------+
                                       |
                   +-------------------+-------------------+
                   |                   |                   |
           +---------------+   +---------------+   +---------------+
           | Serveur 1     |   | Serveur 2     |   | Serveur 3     |
           | Active        |   | Standby       |   | Standby       |
           | 10.0.0.11     |   | 10.0.0.12     |   | 10.0.0.13     |
           | peer_id=0     |   | peer_id=1     |   | peer_id=2     |
           +---------------+   +---------------+   +---------------+
                   |                   |                   |
                   +-------------------+-------------------+
                                       |
                              Switch DHCP/VLAN
                                       |
                        +---------------------------+
                        |   Réseau Clients WiFi    |
                        |   192.168.0.0/16          |
                        |   15,000 utilisateurs     |
                        +---------------------------+
```

## Configuration par Serveur

### Serveur 1 (Master/Active) - 10.0.0.11

**Fichier: `/etc/coovachilli/config.yaml`**

```yaml
# ========== GÉNÉRAL ==========
foreground: false
pidfile: /var/run/coovachilli.pid
user: chilli
group: chilli
interval: 3600s

logging:
  dest: syslog
  level: info
  syslog_tag: coovachilli-srv1

# ========== RÉSEAU ==========
tundev: tun0
dhcpif: eth1
net: 192.168.0.0/16
uamlisten: 192.168.0.1
uamport: 3990

# IPv6 (optionnel)
ipv6enable: true
net_v6: fd00::/64
uamlisten_v6: fd00::1

# ========== POOL DHCP - 5000 IPs ==========
# Serveur 1 : 192.168.0.1 - 192.168.19.136
dhcpstart: 192.168.0.10
dhcpend: 192.168.19.136
lease: 3600s
dns1: 8.8.8.8
dns2: 8.8.4.4
dns1_v6: 2001:4860:4860::8888
dns2_v6: 2001:4860:4860::8844

# DHCPv6
dhcpstart_v6: fd00::1000
dhcpend_v6: fd00::2388  # 5000 IPs

# ========== RADIUS ==========
radiuslisten: 10.0.0.11
radiusserver1: 10.0.1.10:1812
radiusserver2: 10.0.1.11:1812
radiusacctserver1: 10.0.1.10:1813
radiusacctserver2: 10.0.1.11:1813
radiussecret: "VOTRE_SECRET_RADIUS_ICI"
radiusnasid: coovachilli-srv1
radiustimeout: 5s
coaport: 3799

# ========== CLUSTER - CONFIGURATION PRIMAIRE ==========
cluster:
  enabled: true
  peerid: 0              # Serveur 1 = Master
  peerkey: "votre-cle-cluster-tres-securisee-256bits"
  interface: eth0        # Interface pour communication inter-serveurs

# ========== PERSISTENCE ==========
sessionpersistence: true
sessionfile: /var/lib/coovachilli/sessions.json

# ========== PORTAIL CAPTIF ==========
uamserver: https://portal.example.com
uamsecret: "VOTRE_UAM_SECRET"
uamallowed:
  - 10.0.1.0/24      # Réseau RADIUS
  - portal.example.com

# ========== WALLED GARDEN ==========
walledgarden:
  allowed_domains:
    - .google.com
    - .microsoft.com
    - portal.example.com
  allowed_ips:
    - 8.8.8.8/32
    - 8.8.4.4/32

# ========== MÉTRIQUES ==========
metrics:
  enabled: true
  type: prometheus
  prometheus:
    enabled: true
    port: 9100
    path: /metrics

# ========== ADMIN API ==========
admin_api:
  enabled: true
  listen: 0.0.0.0:8080
  secret: "ADMIN_API_SECRET"
  dashboard:
    enabled: true
    refresh_interval: 5s
  multisite:
    enabled: true
    sites:
      - id: "srv1"
        name: "Serveur 1"
        url: "http://10.0.0.11:8080"

# ========== SÉCURITÉ ==========
security:
  ids:
    enabled: true
    rules_path: /etc/coovachilli/ids-rules.yaml
  antimalware:
    enabled: true
    max_connections_per_minute: 100

# ========== SCRIPTS ==========
conup: /etc/coovachilli/scripts/connection-up.sh
condown: /etc/coovachilli/scripts/connection-down.sh

# ========== TIMEOUTS ==========
session_timeout: 86400      # 24h par défaut
idle_timeout: 1800          # 30min inactivité
```

---

### Serveur 2 (Standby) - 10.0.0.12

**Fichier: `/etc/coovachilli/config.yaml`**

```yaml
# Même config que Serveur 1, SAUF:

logging:
  syslog_tag: coovachilli-srv2

# ========== POOL DHCP - 5000 IPs ==========
# Serveur 2 : 192.168.19.137 - 192.168.39.16
dhcpstart: 192.168.19.137
dhcpend: 192.168.39.16

# DHCPv6
dhcpstart_v6: fd00::2389
dhcpend_v6: fd00::3711

# ========== RADIUS ==========
radiuslisten: 10.0.0.12
radiusnasid: coovachilli-srv2

# ========== CLUSTER ==========
cluster:
  enabled: true
  peerid: 1              # Serveur 2 = Standby
  peerkey: "votre-cle-cluster-tres-securisee-256bits"  # MÊME CLÉ
  interface: eth0

# ========== PERSISTENCE ==========
sessionfile: /var/lib/coovachilli/sessions-srv2.json

# ========== MÉTRIQUES ==========
metrics:
  prometheus:
    port: 9101           # Port différent

# ========== ADMIN API ==========
admin_api:
  listen: 0.0.0.0:8081   # Port différent
  multisite:
    sites:
      - id: "srv2"
        name: "Serveur 2"
        url: "http://10.0.0.12:8081"
```

---

### Serveur 3 (Standby) - 10.0.0.13

**Fichier: `/etc/coovachilli/config.yaml`**

```yaml
# Même config que Serveur 1, SAUF:

logging:
  syslog_tag: coovachilli-srv3

# ========== POOL DHCP - 5000 IPs ==========
# Serveur 3 : 192.168.39.17 - 192.168.58.152
dhcpstart: 192.168.39.17
dhcpend: 192.168.58.152

# DHCPv6
dhcpstart_v6: fd00::3712
dhcpend_v6: fd00::4a38

# ========== RADIUS ==========
radiuslisten: 10.0.0.13
radiusnasid: coovachilli-srv3

# ========== CLUSTER ==========
cluster:
  enabled: true
  peerid: 2              # Serveur 3 = Standby
  peerkey: "votre-cle-cluster-tres-securisee-256bits"  # MÊME CLÉ
  interface: eth0

# ========== PERSISTENCE ==========
sessionfile: /var/lib/coovachilli/sessions-srv3.json

# ========== MÉTRIQUES ==========
metrics:
  prometheus:
    port: 9102           # Port différent

# ========== ADMIN API ==========
admin_api:
  listen: 0.0.0.0:8082   # Port différent
  multisite:
    sites:
      - id: "srv3"
        name: "Serveur 3"
        url: "http://10.0.0.13:8082"
```

---

## Configuration HAProxy (Load Balancer)

**Fichier: `/etc/haproxy/haproxy.cfg`**

```haproxy
global
    log /dev/log local0
    maxconn 50000
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

# ========== DHCP Load Balancing ==========
# Round-robin sur les 3 serveurs
frontend dhcp_frontend
    bind *:67
    mode udp
    default_backend dhcp_servers

backend dhcp_servers
    mode udp
    balance roundrobin
    server srv1 10.0.0.11:67 check inter 2000 rise 2 fall 3
    server srv2 10.0.0.12:67 check inter 2000 rise 2 fall 3
    server srv3 10.0.0.13:67 check inter 2000 rise 2 fall 3

# ========== HTTP Portail Captif ==========
frontend http_frontend
    bind *:3990
    mode http
    default_backend http_servers

backend http_servers
    mode http
    balance leastconn      # Connexion la moins chargée
    option httpchk GET /ping
    server srv1 10.0.0.11:3990 check inter 2000 rise 2 fall 3
    server srv2 10.0.0.12:3990 check inter 2000 rise 2 fall 3
    server srv3 10.0.0.13:3990 check inter 2000 rise 2 fall 3

# ========== Admin Dashboard ==========
frontend admin_frontend
    bind *:8080
    mode http
    default_backend admin_servers

backend admin_servers
    mode http
    balance roundrobin
    server srv1 10.0.0.11:8080 check
    server srv2 10.0.0.12:8081 check
    server srv3 10.0.0.13:8082 check

# ========== Métriques Prometheus ==========
listen prometheus_metrics
    bind *:9100
    mode http
    stats enable
    stats uri /haproxy_stats
    server srv1 10.0.0.11:9100 check
    server srv2 10.0.0.12:9101 check
    server srv3 10.0.0.13:9102 check
```

---

## Scripts de Déploiement

### 1. Installation sur chaque serveur

**Fichier: `deploy.sh`**

```bash
#!/bin/bash
# Script d'installation CoovaChilli sur Ubuntu 22.04

set -e

SERVER_ID=$1  # 1, 2 ou 3

if [[ -z "$SERVER_ID" ]]; then
    echo "Usage: $0 <server_id>"
    echo "Example: $0 1"
    exit 1
fi

echo "=== Installation CoovaChilli Serveur $SERVER_ID ==="

# 1. Créer utilisateur
sudo useradd -r -s /bin/false chilli || true

# 2. Créer répertoires
sudo mkdir -p /etc/coovachilli/scripts
sudo mkdir -p /var/lib/coovachilli
sudo mkdir -p /var/log/coovachilli

# 3. Copier binaire
sudo cp coovachilli /usr/local/bin/
sudo chmod +x /usr/local/bin/coovachilli

# 4. Copier configuration
sudo cp config-server${SERVER_ID}.yaml /etc/coovachilli/config.yaml
sudo chmod 600 /etc/coovachilli/config.yaml
sudo chown chilli:chilli /etc/coovachilli/config.yaml

# 5. Configurer systemd
cat <<EOF | sudo tee /etc/systemd/system/coovachilli.service
[Unit]
Description=CoovaChilli Captive Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=chilli
Group=chilli
ExecStart=/usr/local/bin/coovachilli -c /etc/coovachilli/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

# Sécurité
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/coovachilli /var/log/coovachilli
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# 6. Activer IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf

# 7. Configurer firewall
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 8. Persister règles iptables
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# 9. Démarrer service
sudo systemctl daemon-reload
sudo systemctl enable coovachilli
sudo systemctl start coovachilli

echo "=== Installation terminée ==="
echo "Status: sudo systemctl status coovachilli"
echo "Logs: sudo journalctl -u coovachilli -f"
```

### 2. Script de monitoring

**Fichier: `monitor-cluster.sh`**

```bash
#!/bin/bash
# Monitoring du cluster 3 serveurs

SERVERS=("10.0.0.11:8080" "10.0.0.12:8081" "10.0.0.13:8082")

echo "=== CoovaChilli Cluster Status ==="
echo "Date: $(date)"
echo ""

for i in "${!SERVERS[@]}"; do
    SERVER="${SERVERS[$i]}"
    SERVER_ID=$((i+1))

    echo "--- Serveur $SERVER_ID ($SERVER) ---"

    # Test API
    if curl -s --connect-timeout 2 "http://$SERVER/api/stats" > /dev/null; then
        SESSIONS=$(curl -s "http://$SERVER/api/stats" | jq -r '.active_sessions // 0')
        AUTHENTICATED=$(curl -s "http://$SERVER/api/stats" | jq -r '.authenticated_sessions // 0')
        UPTIME=$(curl -s "http://$SERVER/api/stats" | jq -r '.uptime // "N/A"')

        echo "  Status: ✓ UP"
        echo "  Sessions: $SESSIONS (Auth: $AUTHENTICATED)"
        echo "  Uptime: $UPTIME"
    else
        echo "  Status: ✗ DOWN"
    fi
    echo ""
done

# Total
TOTAL=$(curl -s "http://10.0.0.11:8080/api/stats" "http://10.0.0.12:8081/api/stats" "http://10.0.0.13:8082/api/stats" | jq -s 'map(.active_sessions // 0) | add')
echo "=== Total Sessions: $TOTAL / 15000 ==="
```

---

## Procédure de Déploiement

### Étape 1: Préparation (sur votre machine de build)

```bash
# 1. Compiler le binaire
cd /IdeaProjects/coovachilli-go
go build -o coovachilli ./cmd/coovachilli

# 2. Créer les 3 configs
cp docs/config-server1.yaml .
cp docs/config-server2.yaml .
cp docs/config-server3.yaml .

# Éditer les secrets dans chaque fichier:
# - radiussecret
# - uamsecret
# - cluster.peerkey
# - admin_api.secret
```

### Étape 2: Déploiement sur les serveurs

```bash
# Sur chaque serveur
SERVER_ID=1  # Changer pour 2, 3

# Copier fichiers
scp coovachilli root@10.0.0.1${SERVER_ID}:/tmp/
scp config-server${SERVER_ID}.yaml root@10.0.0.1${SERVER_ID}:/tmp/
scp deploy.sh root@10.0.0.1${SERVER_ID}:/tmp/

# Installer
ssh root@10.0.0.1${SERVER_ID}
cd /tmp
chmod +x deploy.sh
./deploy.sh $SERVER_ID
```

### Étape 3: Vérification

```bash
# Sur chaque serveur
sudo systemctl status coovachilli
sudo journalctl -u coovachilli -f

# Vérifier clustering
curl http://10.0.0.11:8080/api/stats
curl http://10.0.0.12:8081/api/stats
curl http://10.0.0.13:8082/api/stats
```

### Étape 4: Monitoring Prometheus/Grafana

```bash
# Ajouter dans prometheus.yml
scrape_configs:
  - job_name: 'coovachilli'
    static_configs:
      - targets:
        - '10.0.0.11:9100'
        - '10.0.0.12:9101'
        - '10.0.0.13:9102'
```

---

## Tests de Charge

### Test 1: Authentification simultanée

```bash
# Simuler 100 connexions/seconde
for i in {1..100}; do
    (curl -X POST http://192.168.0.1:3990/login \
        -d "username=user$i&password=pass$i" &)
done
```

### Test 2: Failover automatique

```bash
# Arrêter serveur actif
ssh root@10.0.0.11 "systemctl stop coovachilli"

# Vérifier élection nouveau master
sleep 5
curl http://10.0.0.12:8081/api/stats | jq '.cluster_state'
```

---

## Dimensionnement

### Ressources par serveur (5000 users)

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| CPU       | 4 cores | 8 cores    |
| RAM       | 8 GB    | 16 GB      |
| Disque    | 50 GB   | 100 GB SSD |
| Réseau    | 1 Gbps  | 10 Gbps    |

### Calculs

```
15000 utilisateurs × 100 KB/s moyen = 1.5 Gbps
Chaque serveur: 5000 × 100 KB/s = 500 Mbps
RAM sessions: 15000 × 2 KB ≈ 30 MB (négligeable)
```

---

## Maintenance

### Mise à jour rolling

```bash
# 1. Arrêter Serveur 3 (Standby)
ssh root@10.0.0.13 "systemctl stop coovachilli"

# 2. Mettre à jour
scp coovachilli root@10.0.0.13:/usr/local/bin/
ssh root@10.0.0.13 "systemctl start coovachilli"

# 3. Répéter pour Serveur 2
# 4. Répéter pour Serveur 1 (basculer Active vers Srv2 avant)
```

### Backup sessions

```bash
# Cron quotidien sur chaque serveur
0 2 * * * /usr/bin/rsync -az /var/lib/coovachilli/sessions*.json backup-server:/backups/srv$(hostname)/
```

---

## Troubleshooting

### Cluster ne se synchronise pas

```bash
# Vérifier connectivité
ping -c 3 10.0.0.11
ping -c 3 10.0.0.12
ping -c 3 10.0.0.13

# Vérifier peerkey identique
grep peerkey /etc/coovachilli/config.yaml
```

### Utilisateurs n'obtiennent pas d'IP

```bash
# Vérifier pools DHCP non chevauchants
# Srv1: 192.168.0.10 - 192.168.19.136
# Srv2: 192.168.19.137 - 192.168.39.16
# Srv3: 192.168.39.17 - 192.168.58.152

# Tester DHCP
sudo tcpdump -i eth1 -n port 67 or port 68
```

### Performance dégradée

```bash
# Vérifier métriques
curl http://10.0.0.11:9100/metrics | grep coovachilli

# Top processus
top -p $(pgrep coovachilli)

# Connexions réseau
ss -tunap | grep coovachilli
```

---

## Contacts & Support

- Documentation: https://github.com/votre-repo/coovachilli-go
- Issues: https://github.com/votre-repo/coovachilli-go/issues
- Slack: #coovachilli-support
