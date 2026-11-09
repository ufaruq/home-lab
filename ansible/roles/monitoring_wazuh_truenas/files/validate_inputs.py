"""Validate literal bind/source values before interpolating privileged config."""
import ipaddress
import sys


def validate(address, source):
    networks = tuple(ipaddress.ip_network(n) for n in
                     ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    values = [ipaddress.ip_address(v) for v in (address, source)]
    if any(v.version != 4 or not any(v in n for n in networks) for v in values):
        raise ValueError('Exact RFC1918 IPv4 literals are required')
    if address == source:
        raise ValueError('Receiver and appliance must have distinct addresses')


if __name__ == '__main__':
    validate(*sys.argv[1:])
