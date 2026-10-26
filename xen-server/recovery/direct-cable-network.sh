#!/bin/sh
# Addresses and physical-port identity belong only in the root-private policy.
# home-lab: private-recovery-policy-v1
set -eu
configuration=${DIRECT_CABLE_NETWORK_CONFIG:-/etc/home-lab/direct-cable-network.conf}
[ -f "$configuration" ] && [ ! -L "$configuration" ] || { echo "Required private recovery policy is missing" >&2; exit 1; }
[ "$(/usr/bin/stat -c %u "$configuration")" = 0 ] || { echo "Recovery policy must be root-owned" >&2; exit 1; }
mode=$(/usr/bin/stat -c %a "$configuration")
[ "$mode" = 600 ] || [ "$mode" = 400 ] || { echo "Recovery policy must have mode 0600 or 0400" >&2; exit 1; }
unset RECOVERY_PORT_MAC RECOVERY_ADDRESSES
. "$configuration"
: "${RECOVERY_PORT_MAC:?Private RECOVERY_PORT_MAC is required}"
: "${RECOVERY_ADDRESSES:?Private RECOVERY_ADDRESSES is required}"
expected_mac=
check=false
if [ "$#" -gt 0 ]; then
    [ "$1" = --check ] || { echo "Only --check is supported" >&2; exit 1; }
    check=true
    shift
    if [ "$#" -gt 0 ]; then
        [ "$#" = 2 ] && [ "$1" = --expect-mac ] || exit 1
        expected_mac=$2
    fi
fi
/usr/bin/python -c 'import re,socket,sys
mac,addresses,expected=sys.argv[1:]
if not re.match(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$",mac) or (expected and expected!=mac):sys.exit("Recovery MAC differs from reviewed policy")
for address in addresses.split():
 try:
  value,prefix=address.split("/");socket.inet_pton(socket.AF_INET,value)
  if not 0<=int(prefix)<=32:raise ValueError()
 except (ValueError,socket.error):sys.exit("Invalid private recovery CIDR")
if not addresses.split():sys.exit("No private recovery CIDRs")' "$RECOVERY_PORT_MAC" "$RECOVERY_ADDRESSES" "$expected_mac"
device=
attempt=0
while [ "$attempt" -lt 30 ]; do
    for port in /sys/class/net/*; do
        [ -r "$port/address" ] || continue
        read -r address < "$port/address"
        if [ "$address" = "$RECOVERY_PORT_MAC" ]; then
            device=${port##*/}
            break
        fi
    done
    [ -z "$device" ] || break
    attempt=$((attempt + 1))
    sleep 1
done
[ -n "$device" ] || { echo "Reviewed recovery port was not found" >&2; exit 1; }
if [ "$check" = true ]; then
    echo "Private recovery policy and physical-port identity verified"
    exit 0
fi
/usr/sbin/ip link set dev "$device" up
target=$device
if bridge=$(/usr/bin/ovs-vsctl --timeout=2 iface-to-br "$device" 2>/dev/null); then
    if [ -n "$bridge" ] && [ -d "/sys/class/net/$bridge" ]; then
        target=$bridge
    fi
fi
/usr/sbin/ip link set dev "$target" up
for address in $RECOVERY_ADDRESSES; do
    /usr/sbin/ip address replace "$address" dev "$target"
done
echo "Private direct-recovery address policy applied"
