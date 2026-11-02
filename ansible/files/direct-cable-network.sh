#!/bin/sh
# The private root-owned profile supplies the physical MAC and recovery aliases.
set -eu
config=/etc/home-lab/direct-cable-network.conf
[ -r "$config" ] || { echo "Missing reviewed recovery network profile" >&2; exit 1; }
. "$config"
: "${RECOVERY_PORT_MAC:?Missing recovery port MAC}"
: "${RECOVERY_ADDRESSES:?Missing recovery addresses}"
device=
attempt=0
while [ "$attempt" -lt 30 ]; do
    for port in /sys/class/net/*; do
        [ -r "$port/address" ] || continue
        read -r address < "$port/address"
        if [ "$address" = "$RECOVERY_PORT_MAC" ]; then device=${port##*/}; break; fi
    done
    [ -z "$device" ] || break
    attempt=$((attempt + 1))
    sleep 1
done
[ -n "$device" ] || { echo "Reviewed recovery port not found" >&2; exit 1; }
/usr/sbin/ip link set dev "$device" up
bridge=$(/usr/bin/ovs-vsctl --timeout=2 iface-to-br "$device" 2>/dev/null) || {
    echo "Waiting for the native Open vSwitch bridge" >&2; exit 1;
}
[ -n "$bridge" ] && [ -d "/sys/class/net/$bridge" ] || {
    echo "Native recovery bridge is not ready" >&2; exit 1;
}
target=$bridge
/usr/sbin/ip link set dev "$target" up
for address in $RECOVERY_ADDRESSES; do
    # Remove only declared legacy aliases from the physical port before moving
    # them to its bridge. Never leave the same local IP owned by both devices.
    physical=$(/usr/sbin/ip -o -4 address show dev "$device")
    case "$physical" in
        *" inet $address "*) /usr/sbin/ip address del "$address" dev "$device" ;;
    esac
    current=$(/usr/sbin/ip -o -4 address show dev "$target")
    case "$current" in
        *" inet $address "*) ;;
        *) /usr/sbin/ip address replace "$address" dev "$target" ;;
    esac
done
echo "Reviewed direct recovery aliases configured on $target"
