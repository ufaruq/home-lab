#!/bin/sh
# Read-only commands. Never read shadow, private keys, env files, config bodies or Docker Env.
set -u
section() { printf '\n=== %s ===\n' "$1"; }
section OS
uname -srm
if [ -r /etc/os-release ]; then sed -n '/^\(NAME\|VERSION\|ID\|VERSION_ID\)=/p' /etc/os-release; fi
section USERS
if command -v getent >/dev/null 2>&1; then getent passwd; else cat /etc/passwd; fi | awk -F: '{print $1 ":" $3 ":" $4 ":" $6 ":" $7}'
section GROUPS
if command -v getent >/dev/null 2>&1; then getent group; else cat /etc/group; fi | awk -F: '{print $1 ":" $3 ":" $4}'
section PACKAGES
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n';
elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n';
elif command -v pkg >/dev/null 2>&1; then pkg query '%n\t%v'; fi
section SERVICES
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --no-pager --no-legend
  systemctl list-units --type=service --all --no-pager --no-legend
elif command -v service >/dev/null 2>&1; then service -l; fi
section NETWORK
if command -v ip >/dev/null 2>&1; then ip -brief address; ip route show; ip -6 route show;
elif command -v ifconfig >/dev/null 2>&1; then ifconfig; netstat -rn; fi
if command -v ss >/dev/null 2>&1; then ss -lntup; fi
section MOUNTS
# Exclude mount option strings, which can carry credentials.
if command -v findmnt >/dev/null 2>&1; then findmnt -rn -o SOURCE,TARGET,FSTYPE;
else df -P; fi
section BLOCK_METADATA
if command -v lsblk >/dev/null 2>&1; then lsblk -o NAME,TYPE,FSTYPE,SIZE,UUID,MOUNTPOINT; fi
section DOCKER_METADATA
if command -v docker >/dev/null 2>&1; then
  docker version --format 'client={{.Client.Version}} server={{if .Server}}{{.Server.Version}}{{end}}' 2>/dev/null || true
  docker ps -a --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
  docker volume ls --format '{{.Driver}}\t{{.Name}}' 2>/dev/null || true
fi
section APPLICATION_CONFIG_FILE_METADATA
# Presence is evidence; VM display names are not evidence of installed applications.
# Only filenames/type/owner/mode/size are returned, never config contents or hashes.
for p in /etc/docker /opt/portainer /var/lib/portainer /var/ossec/etc /etc/wazuh-indexer /etc/wazuh-dashboard /opt/stacks /opt/compose /srv/compose /conf/config.xml /data/freenas-v1.db; do
  if [ -e "$p" ]; then
    if command -v stat >/dev/null 2>&1; then ls -ldn "$p"; fi
    if [ -d "$p" ]; then find "$p" -xdev -maxdepth 2 -type f -exec ls -ldn {} \; 2>/dev/null; fi
  fi
done
section DISCOVERY_LIMITS
printf '%s\n' 'Config bodies, secrets, application database contents, firewall policy, container environment and running workloads are not captured by this metadata audit.'
