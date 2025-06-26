#!/bin/bash

# ---------------------------------------------------------
# Wazuh Stack Automated Installer for SOC environments
# Author: Alikhan Karabaev (AlikhanKarabaevNEWPROJECT)
# GitHub: https://github.com/AlikhanKarabaevNEWPROJECT/wazuh-installer
# Date: 2025-06-26
# Description: Fully automated installation of Wazuh Indexer,
#              Manager, Filebeat, and Dashboard on Debian.
# ---------------------------------------------------------


set -e

# Получаем IP и hostname
IP=$(hostname -I | awk '{print $1}')
HN=$(hostname)

echo "[+] Установка зависимостей..."
apt-get update
apt-get install -y curl gnupg apt-transport-https debconf adduser procps tar libcap2-bin debhelper

# Добавление репозитория ВАЗУХА
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update

# сертификаты
curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
cat <<EOF > ./config.yml
nodes:
  indexer:
    - name: $HN
      ip: $IP
  server:
    - name: wazuh-1
      ip: $IP
  dashboard:
    - name: dashboard
      ip: $IP
EOF

bash ./wazuh-certs-tool.sh -A

# очистка
TAR_NAME=wazuh-certificates.tar
tar -cvf $TAR_NAME -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

# Wazuh Indexer
apt-get install -y wazuh-indexer

cat <<EOF > /etc/wazuh-indexer/opensearch.yml
network.host: $IP
node.name: $HN
cluster.initial_master_nodes:
- $HN
cluster.name: "wazuh-cluster"
node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.nodes_dn:
- "CN=$HN,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
compatibility.override_main_response_version: true
EOF

mkdir -p /etc/wazuh-indexer/certs
cd /etc/wazuh-indexer/certs

tar -xf /root/$TAR_NAME -C . ./debian.pem ./debian-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv debian.pem indexer.pem
mv debian-key.pem indexer-key.pem
chmod 500 .
chmod 400 *
chown -R wazuh-indexer:wazuh-indexer .

systemctl daemon-reload
systemctl enable --now wazuh-indexer
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

#  Wazuh Manager
apt-get install -y wazuh-manager
systemctl enable --now wazuh-manager

# Установка Filebeat
apt-get install -y filebeat
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.12.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

mkdir -p /etc/filebeat/certs
cd /etc/filebeat/certs

tar -xf /root/$TAR_NAME -C . ./wazuh-1.pem ./wazuh-1-key.pem ./root-ca.pem
mv wazuh-1.pem filebeat.pem
mv wazuh-1-key.pem filebeat-key.pem
chmod 500 .
chmod 400 *
chown -R root:root .

cat <<EOF > /etc/filebeat/filebeat.yml
output.elasticsearch:
  hosts: ["$IP:9200"]
  protocol: https
  username: \${username}
  password: \${password}
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
logging.metrics.enabled: false
seccomp:
  default_action: allow
  syscalls:
    - action: allow
      names:
        - rseq
EOF

filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force
systemctl enable --now filebeat

#  Wazuh Dashboard
apt-get install -y wazuh-dashboard
mkdir -p /etc/wazuh-dashboard/certs
cd /etc/wazuh-dashboard/certs

tar -xf /root/$TAR_NAME -C . ./dashboard.pem ./dashboard-key.pem ./root-ca.pem
chmod 500 .
chmod 400 *
chown -R wazuh-dashboard:wazuh-dashboard .

cat <<EOF > /etc/wazuh-dashboard/opensearch_dashboards.yml
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://$IP:9200
opensearch.ssl.verificationMode: certificate
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
EOF

systemctl enable --now wazuh-dashboard

echo -e "\n[✓] Установка Wazuh завершена. Интерфейс: https://$IP/"
