DNS is insecure because by default DNS queries are not encrypted, which can be exploited by middle entities. DNS cache poison is one of the DNS abuses that is widely used by the Great Firewall of China (GFW) to censor Chinese Internet. GFW checks every DNS query that is sent to a DNS server outside of China. Since plain text DNS protocol is based on UDP, which is a connection-less protocol, GFW can spoof both the client IP and server IP.  When GFW finds a domain name on its block list, it changes the DNS response. For example, if a Chinese Internet user wants to visit google.com, the Great firewall of China returns to the DNS resolver an IP address located in China instead of Google’s real IP address. Then the DNS resolver returns the fake IP address to the user’s computer.
What is DNS over TLS? How It Protects Your Privacy?

DNS over TLS means that DNS queries are sent over a secure connection encrypted with TLS, the same technology that encrypts HTTP traffic, so no third parties can see your DNS queries. Together with HTTPS and encrypted SNI (Server Name Indication), your browsing history is fully protected from ISP spying.


Stubby is in debian or devuan unstable repo.You can easily add the unstable repo and limiting it to prevent your system to upgrade entirely to unstable


echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list

printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable

apt update

apt install wireguard
sudo apt install stubby

This will install stubby and the getdns library. Once installed, stubby runs in the background. You you check its status with:

systemctl status stubby

ubuntu stubby

Stubby listens on TCP and UDP port 53 of localhost (127.0.0.1), as can be seen by running this command:

sudo netstat -lnptu | grep stubby

stubby dns over tls

The default stub resolver provided by systemd-resolved listens on TCP and UDP port 53 of 127.0.0.53.

sudo netstat -lnptu | grep systemd-resolve

systemd-resolved stub resolver
Note: If dnsmasq is listening on TCP port 53 of 127.0.0.1, then Stubby will listen only on UDP port 53 of 127.0.0.1.

The main configuration file is /etc/stubby/stubby.yml. Normally there’s no need to make changes to it unless you want to use another or your own recursive resolver. Let me explain some default configurations. You can open the file with:

sudo nano /etc/stubby/stubby.yml

The following line makes stubby run as a stub resolver instead of a full recursive resolver, which is why it’s named stubby.

resolution_type: GETDNS_RESOLUTION_STUB

The following configuration make stubby send DNS queries encrypted with TLS. It will not send quries in plain text.

dns_transport_list:
- GETDNS_TRANSPORT_TLS

This following line requires a valid TLS certificate on the remote recursive resolver.

tls_authentication: GETDNS_AUTHENTICATION_REQUIRED

The following lines set the listen addresses for the stubby daemon. By default, IPv4 and IPv6 are both enabled.

listen_addresses:
- 127.0.0.1
- 0::1

The following line make stubby query recursive resolvers in a round-robin fashion. If set to 0, Stubby will use each upstream server sequentially until it becomes unavailable and then move on to use the next.

round_robin_upstreams: 1

By default there are 3 recursive resolvers enabled in stubby configuration file. They are run by stubby developers and support DNS over TLS. You can see the full list of recommended servers on DNS Privacy website.

dnsovertls.sinodun.com     145.100.185.15
dnsovertls1.sinodun.com    145.100.185.16
getdnsapi.net              185.49.141.37

There are other DNS servers in the Additional Servers section that are disabled by default.

dns.quad9.net
unicast.censurfridns.dk
dnsovertls3.sinodun.com (supporting TLS1.2 and TLS 1.3)
dnsovertls2.sinodun.com
dns.cmrg.net
dns.larsdebruin.net
......

There are also DNS servers listening on port 443. If port 853 is blocked in your network, you can uncomment them to use these servers.

dnsovertls.sinodun.com
dnsovertls1.sinodun.com
dns.cmrg.net
dns.neutopia.org

Now you can exit nano text editor by pressing Ctrl+X.
Switching to Stubby

Editing the /etc/resolve.conf file to change name server is not recommended any more. Follow the instructions below to make systemd-resolved send DNS queries to stubby.
GNOME Desktop

Click the Network Manager icon on the upper-right corner of your desktop. Then select wired settings. (If you are using Wi-fi, select Wi-fi settings.)

encrypt dns

Click the gear button.

cloudflare dns over tls

Select IPv4 tab, then in DNS settings, switch Automatic to OFF, which will prevent your Ubuntu system from getting DNS server address from your router. Enter 127.0.0.1 in the DNS field. Click Apply button to save your changes.

dns over tls port 853

Then restart NetworkManager for the changes to take effect.

sudo systemctl restart NetworkManager

Once you are reconnected, you can see that your Ubuntu system is now using 127.0.0.1 as the DNS server in the Details tab.

stub resolver dns over tls
Unity Desktop

Recommended reading: how to install Unity desktop environment on Ubuntu 18.04.

Click the Network Manager icon on the upper-right corner of your desktop, then click edit connections.

network manager change DNS

Select your connection name and click the gear icon.

stubby systemd-resolved

Select IPv4 settings tab, change method from Automatic(DHCP) to Automatic(DHCP) addresses only, which will prevent your Ubuntu system from getting DNS server address from your router. Then specify a DNS server (127.0.0.1). Stubby listens on 127.0.0.1.

ubuntu dns over tls

Save your changes. Then restart NetworkManager for the changes to take effect.

sudo systemctl restart NetworkManager

Once you are reconnected, click the Network Manager icon again and select connection information. You can see that your Ubuntu system is now using 127.0.0.1 as the DNS server.

ubuntu 18.04 dns over tls
A Desktop-Agnostic Way to Change DNS Server

You can use the method below to change DNS server as only as your desktop environment is using NetworkManager.

Open a terminal window and go to the Network Manager connections profile directory.

cd /etc/NetworkManager/system-connections/

Then list connection names available on your system.

ls

network manager change dns server from command line

As you can see, I have several connections on my system, one of which is wired connection. Some are wireless connections and one is VPN connection. Because my desktop computer is connected to my router via an Ethernet cable, so I need to edit the wired connection profile with the nano command line text editor.

sudo nano 'Wired connection 1'

If your computer is connected via Wi-fi, then you need to edit the wireless connection profile. In this file, find the [ipv4] configurations. By default, it should look like this:

[ipv4]
dns-search=
method=auto

To make your system use Stubby, change the configurations to the following.

[ipv4]
dns=127.0.0.1;
dns-search=
ignore-auto-dns=true
method=auto

To save the file in Nano text editor, press Ctrl+O, then press Enter to confirm. Press Ctrl+X to exit. Then restart Network Manager for the changes to take effect.

sudo systemctl restart NetworkManager

You can now check your current DNS server by running the following command:

systemd-resolve --status

Sample output:

Link 2 (enp5s0)
Current Scopes: DNS
LLMNR setting: yes
MulticastDNS setting: no
DNSSEC setting: no
DNSSEC supported: no
DNS Servers: 127.0.0.1

If 127.0.0.1 is listed as the DNS server, then your system is using Stubby.
How to Check if Your DNS Traffic is Encrypted

We can use WireShark to monitor DNS traffic. Install WireShark from Ubuntu 18.04 repository.

sudo apt install wireshark

If you are asked “Should non-superusers be able to capture packets?”, answer Yes. Once it’s installed, run the following command to add your user account to the wireshark group so that you can capture packets.

sudo adduser your-username wireshark

Log out and log back in for the changes to take effect. Then open WireShark from your application menu, select your network interface in WireShark. For example, my Ethernet interface name is enp5s0. Then enter port 853 as the capture filter. This will make WireShark only capture traffic on port 853, which is the port used by DNS over TLS.

ubuntu 18.04 stubby

Click the button on the upper-left corner to start capturing. After that, in terminal window, run the following command to query domain name by using the dig utility. For instance, I can query the A record of my domain name.

dig A linuxbabe.com

Now you can see the captured DNS traffic in WireShark. As you can see, my DNS query was sent to 185.49.141.37, 145.100.185.15 and 145.100.185.16, which are the 3 default DNS resolvers defined in stubby configuration file. Connections were made over TCP and encrypted with TLS, which is what I want.

secure dns

If DNS queries are sent without encryption, then the computer would contact DNS server on port 53. You can capture packets again with port 53 as the capture filter, but you won’t see any packets in WireShark, which means stubby is encrypting your DNS queries.
How to Add CloudFlare DNS to Stubby

I found that there is high latency (over 200ms) between my computer and the 3 default DNS servers, whereas CloudFlare DNS servers (1.1.1.1, 1.0.0.1) give me very low latency (below 20ms). CloudFlare also supports DNS over TLS. To add CloudFlare DNS server, edit stubby configuration file.

sudo nano /etc/stubby/stubby.yml

Scroll down to the upstream_recursive_servers: section and add the following text above other DNS servers.

#CloudFlare servers
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"

Then find the following line:

round_robin_upstreams: 1

Change 1 to 0. This will make stubby always use CloudFlare DNS server. If CloudFlare is not available, stubby will use other DNS servers. Save the file and restart stubby for the changes to take effect.

sudo systemctl restart stubby
