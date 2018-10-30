PIWALL
Designed initially for an Alpine Linux Raspberry Pi but should be distro neutral

CONCEPT:

A stateful firewall/router utilising iptables. It acts as a bridge between the internet and a home LAN. Typically this would be serving the LAN as a wireless accesspoint, therefore MAC filtering functionality has been added. Edit the known_mac_addresses file to add the anticipated MACs on your network. Change the user_variables file to meet your network topology and things such as desired ports. There is a separate variable for custom ssh ports to limit ssh connectivity to specific MAC addresses.

Based loosely around Michael Rash's iptables.sh in "Linux Firewalls" but written in an uglier style with some junk thrown in.


IMPORTANT NOTE:
Currently probably not working. Written for an experimental box, pushed early to avoid self-destruct/disappointment. Use at own risk.
