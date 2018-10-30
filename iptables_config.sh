#Based on iptables.sh from Michael Rash's Linux Firewalls book. Added dropping external echo requests; custom ssh port config; MAC filtering and condensed the script considerably

########################################################################################################
#----------------------------------------DEPENDENCIES--------------------------------------------------#
#  The following modules must be flagged as loadable (m) or compiled (y) in /boot/config-$(uname -r):  #
#______________________________________________________________________________________________________#
#                                                                                                      #   
#  CONFIG_NETFILTER_XT_MATCH_MAC  -- mac address filtering for $ipt                                # 
#  CONFIG_NF_CONNTRACK            -- track established connections (stateful firewall functionality)   #
#  CONFIG_NF_CONNTRACK_FTP        -- track ftp connections                                             #
#  CONFIG_IP_NF_NAT               -- enable NAT filtering                                              #
#  CONFIG_NF_NAT_FTP              -- does a thing, presumably tracks Natted FTP requests... maybe      #
########################################################################################################

#________________________________________VARIABLES

#--------------USER DEFINED
#user vars are imported from user_variables. Nothing in this script should require modification by the end user
source user_variables


#--------------INBUILT

#Command aliases
ipt="/sbin/iptables"
modp="/sbin/modprobe"

#LAN subnet
internal=$(ip -o a | awk -v nic=$lan_nic '$0~nic{print $4}')

#MAC addresses permitted onto the internal network. Insert the MAC addresses into the known_mac_addresses file provided with this script 
macaddr=( $(sed 's/#.*$//' known_mac_addresses) )

#Workstations allowed to use ssh to this host
ssh_wks=( $(sed -n 's/#.*ENABLE\sSSH.*$//p' known_mac_addresses)

#Utilised on a case-by-case basis later for MAC filtering
mac=""

#Direction changes to match the cahing (ie INPUT, OUTPUT or FORWARD) throughout the script. Dopt is directional/interface flag
direction=""
dopt=""


#________________________________________FUNCTIONS


#Simple state-based filtering
#INVALID packets do not relate to any existing connection, eg a random TCP FIN or ACK packet that cannot be traced to an existing handshake. This function logs, then drops these packets
function handle_state(){
    $ipt -A $direction -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
    $ipt -A $direction -m state --state INVALID -j DROP
    $ipt -A $direction -m state --state ESTABLISHED,RELATED -j ACCPT
}

#Handles spoofed packets
function handle_spoof(){
    $ipt -A $direction $dopt $lan_int -s ! $internal -j DROP
}

#ICMP handler -- drop connections originating from the outside world but accept from the local network
function handle_icmp(){
    $ipt -A $direction -s ! $internal -p icmp -m state --state NEW -j DROP
    $ipt -A $direction -s ! $internal -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
    $ipt -A $direction -s $internal -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
}

#Handles outbound connections to permitted ports
function handle_ports(){
    $ipt -A $direction -p udp --destination-port 53 -m state --state NEW -j ACCEPT
    $ipt -A $direction -s $internal -p tcp multiport --destination-port $ports --syn -m state --state NEW -j ACCEPT
    $ipt -A $direction -s $(hostname -i) -p tcp multiport --destination-port $ports --syn -m state --state NEW -j ACCEPT
}

#Handles MAC addresses that are allowed on the internal network (Designed for WAPs)
function handle_mac(){
    $ipt -A $direction -m mac --mac-source $macaddr -j ACCEPT
}

#Log rule -- logs all the things!
function handle_log(){
    $ipt -A $direction $dopt ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options
    $ipt -A $direction $dopt $lan_nic -s ! $internal -j LOG --log-prefix "SPOOFED PKT "
}

#________________________________________INITIALISATION

#Clean slate

$ipt -F
$ipt -F -t nat
$ipt -X

#Default policy
$ipt -P INPUT DROP
$ipt -P OUTPUT DROP
$ipt -P FORWARD DROP

#Load required modules
$modp ip_conntrack
$modp iptable_nat
$modp ip_conntrack_ftp
$modp ip_nat_ftp
$modp xt_mac

#Turn on kernel forwarding of IPv4 traffic
echo 1 >/proc/sys/net/ipv4/ip_forward

#________________________________________MAIN

#------------------------------------INPUT chain
direction="INPUT"
dopt="-i"
handle_state
handle_spoof
handle_ports
handle_icmp
handle_log

#------------------------------------INPUT chain

direction="OUTPUT"
dopt="-o"
handle_state
handle_ports
handle_icmp
handle_log

#------------------------------------FORWARD chain

direction="FORWARD"
dopt="-i"
handle_state
handle_spoof
handle_ports
handle_icmp
handle_log

#------------------------------------NAT

$ipt -t nat -A POSTROUTING -s $internal -o $wan_nic -j MASQUERADE

#------------------------------------LAN MAC address filtering

#Allow ssh to the localhost only from specified local network MAC addresses - these will have "ENABLE SSH" commented on the same line as the MAC address inside the known_mac_addresses file
[[ $ssh -ne 22 ]] && $ipt -A INPUT --destination-port $sshport -j LOG --log-prefix "Custom port SSH Attempt " --log-ip-options --log-tcp-options

$ipt -A INPUT --destination-port 22 -j LOG --log-prefix "SSH Attempt to generic port " --log-ip-options --log-tcp-options

for wksmac in $ssh_wks; do
    $ipt -A INPUT -p tcp  -i $lan_nic --destination-port $sshport --syn -m mac --mac-source $wksmac -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
done


#Allow only registered MACs to access this host and have their traffic forwarded
for mac in macaddr; do
    $ipt -A INPUT -i $lan_nic -m mac --mac-source ! $mac -m state --state NEW,ESTABLISHED,RELATED -j DROP
    $ipt -A FORWARD -i $lan_nic -m mac --mac-source ! $mac -m state --state NEW,ESTABLISHED,RELATED -j DROP
done


#_______________________________________Closure

#Save the config
iptables-save
