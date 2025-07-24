#!/bin/bash

# ---------------------------------------------------------
# Nice Bro
# Wazuh Stack Auto Installer with Hostname-aware Certs
# Author: Alikhan Karabaev (AlikhanKarabaevNEWPROJECT)
# GitHub: https://github.com/AlikhanKarabaevNEWPROJECT/wazuh-installer
# ---------------------------------------------------------

set -e

IP=$(hostname -I | awk '{print $1}')
HN=$(hostname)

echo "[+] Hostname: $HN"
echo "[+] IP: $IP"
echo "[+] Установка зависимостей..."
apt-get update
apt-get install -y curl gnupg apt-transport-https debconf adduser procps tar libcap2-bin debhelper

# Добавление репозитория
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update

# Генерация сертификатов
curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
cat <<EOF > ./config.yml
nodes:
  indexer:
    - name: $HN
      ip: $IP
  server:
    - name: $HN
      ip: $IP
  dashboard:
    - name: $HN
      ip: $IP
EOF

bash ./wazuh-certs-tool.sh -A

TAR_NAME=wazuh-certificates.tar
tar -cvf $TAR_NAME -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

# Indexer
apt-get install -y wazuh-indexer
mkdir -p /etc/wazuh-indexer/certs
cd /etc/wazuh-indexer/certs
tar -xf /root/$TAR_NAME -C . ./$HN.pem ./$HN-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv $HN.pem indexer.pem
mv $HN-key.pem indexer-key.pem
chmod 500 .
chmod 400 *
chown -R wazuh-indexer:wazuh-indexer .

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
plugins.security.system_indices.indices: [".plugins-ml-*", ".opensearch-notifications-*", ".opensearch-observability", ".opendistro-*"]
compatibility.override_main_response_version: true
EOF

systemctl daemon-reload
systemctl enable --now wazuh-indexer
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

# Manager
apt-get install -y wazuh-manager
systemctl enable --now wazuh-manager

# === Замена ossec.conf с авто-IP ===
cat <<EOF > /var/ossec/etc/ossec.conf
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <integration>
        <name>custom-telegram</name>
        <level>0</level>
        <hook_url>https://api.telegram.org/bot YOUR API KEY/sendMessage</hook_url>
        <alert_format>json</alert_format>
  </integration>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://$IP:9200</host>
    </hosts>
    <user>admin</user>
    <password>admin</password>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>
      <key>/etc/filebeat/certs/filebeat-key.pem</key>
    </ssl>
  </indexer>
 <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>
    <directories check_all="yes">/home</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>192.168.0.1</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_dir>etc/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <wodle name="sca">
    <disabled>no</disabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </wodle>

  <wodle name="integrator">
    <disabled>no</disabled>
    <interval>1m</interval>
  </wodle>
</ossec_config>
EOF

# Filebeat
apt-get install -y filebeat
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.12.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

mkdir -p /etc/filebeat/certs
cd /etc/filebeat/certs
tar -xf /root/$TAR_NAME -C . ./$HN.pem ./$HN-key.pem ./root-ca.pem
mv $HN.pem filebeat.pem
mv $HN-key.pem filebeat-key.pem
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

# Dashboard
apt-get install -y wazuh-dashboard
mkdir -p /etc/wazuh-dashboard/certs
cd /etc/wazuh-dashboard/certs
tar -xf /root/$TAR_NAME -C . ./$HN.pem ./$HN-key.pem ./root-ca.pem
mv $HN.pem dashboard.pem
mv $HN-key.pem dashboard-key.pem
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

echo -e "\n[✓] Установка Wazuh завершена успешно. Открой: https://$IP/"
