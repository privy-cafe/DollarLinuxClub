

This tutorial will be showing you how to set up a local DNS resolver on Ubuntu 18.04, 16.04 with the widely-used BIND9 DNS software. A DNS resolver is known by many names, some of which are listed below. They all refer to the same thing.

    full resolver (in contrast to stub resolver)
    DNS recursor
    recursive DNS server
    recursive resolver

Also be aware that A DNS server can also called a name server. Examples of DNS resolver are 8.8.8.8 (Google public DNS server) and 1.1.1.1 (Cloudflare public DNS server). The OS on your PC also has a resolver, although it’s called stub resolver due to its limited capability. A stub resolver is a small DNS client on the end-user’s computer that receives DNS requests from applications such as Firefox and forward requests to a recursive resolver. Almost every resolver can cache DNS response to improve performance, so they are also called caching DNS server.
Why Run Your Own Local DNS Resolver

Normally, your computer or router uses your ISP’s DNS resolver to query DNS names. Running your own local DNS resolver can speed up DNS lookups, because

    The local DNS resolver only listens to your DNS requests and does not answer other people’s DNS requests, so you have a much higher chance of getting DNS answers directly from the cache on the resolver.
    The network latency between your computer and DNS resolver is eliminated (almost zero), so DNS queries can be sent to root DNS servers more quickly.

If you run a mail server and use DNS blacklists (DNSBL) to block spam, then you are advised to run a local DNS resolver to speed up DNS lookups. If you run your own VPN server on a VPS (Virtual Private Server), it’s also a good practice to install a DNS resolver on the same VPS.

You may also want to run your own DNS resolver if you don’t like your Internet browsing history being stored on a third-party server.

If you own a website and want your own DNS server to handle name resolution for your domain name instead of using your domain registrar’s DNS server, then you will need to set up an authoritative DNS server, which is different from a DNS resolver. BIND can act as an authoritative DNS server and a DNS resolver at the same time, but it’s a good practice to separate the two roles on different boxes. This tutorial shows how to set up a local DNS resolver and because it will be used on local host/local network, no encryption (DNS over TLS or DNS over HTTPS) is needed. Setting up a DoT or DoH server will be discussed in a future article.
Set Up a Local DNS Resolver on Ubuntu 18.04, 16.04 with BIND9

BIND (Berkeley Internet Name Domain) is an open-source DNS server software widely used on Unix/Linux due to it’s stability and high quality. It’s originally developed by UC Berkeley, and later in 1994 its development was moved to Internet Systems Consortium, Inc (ISC).

Run the following command to install BIND 9 on Ubuntu 18.04, 16.04 from default repository. BIND 9 is the current version and BIND 10 is a dead project.

sudo apt update
sudo apt install bind9 bind9utils bind9-doc bind9-host

Check version.

named -v

Sample output:

BIND 9.11.3-1ubuntu1.3-Ubuntu (Extended Support Version) <id:a375815>

To check the version number and build options, run

named -V

BIND version number and build option

By default, BIND automatically starts after installation.You check its status with:

systemctl status bind9

If it’s not running, then start it with:

sudo systemctl start bind9

And enable auto start at boot time:

sudo systemctl enable bind9

The BIND server will run as the bind user, which is created during installation, and listens on TCP and UDP port 53, as can be seen by running the following command:

sudo netstat -lnptu | grep named

ubuntu 18.04 bind9 setup

Usually DNS queries are sent to the UDP port 53. The TCP port 53 is for responses sizes larger than 512 bytes.

The BIND daemon is called named. (A daemon is a piece of software that runs in the background.) The named binary is installed by the bind9 package and there’s another important binary: rndc, the remote name daemon controller, which is installed by the bind9utils package. The rndc binary is used to reload/stop and control other aspects of the BIND daemon. Communication is done over TCP port 953.

For example, we can check the status of the BIND name server.

sudo rndc status

remote name daemon controller
Configurations for a Local DNS Resolver

/etc/bind/ is the directory that contains configurations for BIND.

    named.conf: the primary config file which includes configs of three other files.
    db.root: the root hints file used by DNS resolvers to query root DNS servers. There are 13 groups of root DNS servers, from a.root-servers.net to m.root-servers.net.
    db.127: localhost IPv4 reverse mapping zone file.
    db.local: localhost forward IPv4 and IPv6 mapping zone file.
    db.empty: an empty zone file

Out of the box, the BIND9 server on Ubuntu provides recursive service for localhost and local network clients only. Outside queries will be denied. So you don’t have to edit the configuration files. To get you familiar with BIND 9 configurations, I will show you how to enable recursion service anyway.

The main BIND configuration file /etc/bind/named.conf sources the settings from 3 other files.

    /etc/bind/named.conf.options
    /etc/bind/named.conf.local
    /etc/bind/named.conf.default-zones

To enable recursion service, edit the first file.

sudo nano /etc/bind/named.conf.options

In the options clause, add the following lines. Replace IP addresses in the allow-recursion statement with your own local network addresses.

 // hide version number from clients for security reasons.
 version "not currently available";

 // optional - BIND default behavior is recursion
 recursion yes;

 // provide recursion service to trusted clients only
 allow-recursion { 127.0.0.1; 192.168.0.0/24; 10.10.10.0/24; };

 // enable the query log
 querylog yes;

enable recursion service in bind9

Save and close the file. Then test the config file syntax.

sudo named-checkconf

If the test is successful (indicated by a silent output), then restart BIND9.

sudo systemctl restart bind9

If you have a firewall running on the BIND server, then you need to open port 53 to allow LAN clients to send DNS queries.

sudo ufw allow in from 192.168.0.0/24 to any port 53

This will open TCP and UDP port 53 to the private network 192.168.0.0/24. Then from another computer in the same LAN, we can run the following command to query the A record of google.com. Replace 192.168.0.102 with the IP address of your BIND resolver.

dig A google.com @192.168.0.102

Now on the BIND resolver, check the query log with the following command.

sudo journalctl -eu bind9

This will show the latest log message of the bind9 service unit. I can found the following line in the log, which indicates that a DNS query for google.com’s A record has been received from port 57806 of 192.168.0.103.

named[1162]: client @0x7f4d2406f0f0 192.168.0.103#57806 (google.com): query: google.com IN A +E(0)K (192.168.0.102)

Setting the Default DNS Resolver on Ubuntu 18.04 Server

Systemd-resolved provides the stub resolver on Ubuntu 18.04. As mentioned in the beginning of this article, a stub resolver is a small DNS client on the end-user’s computer that receives DNS requests from applications such as Firefox and forward requests to a recursive resolver.

The default recursive resolver can be seen with this command.

systemd-resolve --status

local dns resolver ubuntu

As you can see, BIND isn’t the default. If you run the following command on the BIND server,

dig A facebook.com

This DNS query can’t be found in BIND log. Instead, you need to explicitly tell dig to use BIND.

dig A facebook.com @127.0.0.1

To set BIND as the default resolver, open the systemd-resolved configuration file.

sudo nano /etc/systemd/resolved.conf

In the [Resolve] section, add the following line.

DNS=127.0.0.1

bind dns resolver

Save and close the file. Then restart systemd-resolved service.

sudo systemctl restart systemd-resolved

Now run the following command to check the default DNS resolver.

systemd-resolve --status

bind9 recursive resolver ubuntu 18.04

The DNS server in the Global section override other DNS servers seen at the end of this command output. Now perform a DNS query without specifying 127.0.0.1.

dig A facebook.com

You will see the DNS query in BIND log, which means BIND is now the default recursive resolver.
Setting the Default DNS Resolver on Ubuntu 16.04 Server

Ubuntu 16.04 uses the resolvconf program to manage DNS resolvers in /etc/resolv.conf file. Install the resolvconf package.

sudo apt install resovlconf

To set BIND as the default resolver on Ubuntu 16.04 server, you need to edit the /etc/resolvconf/resolv.conf.d/head file and add “nameserver 127.0.0.1” to this file, which can be done by running the following command:

echo "nameserver 127.0.0.1" | sudo tee -a /etc/resolvconf/resolv.conf.d/head

The resolver defined in this file will always be the first DNS resolver no matter what. Now restart resolvconf service.

sudo systemctl restart resolvconf

You can now check the content of /etc/resolv.conf.

cat /etc/resolv.conf

ubuntu 16.04 set default DNS resolver

As you can see, 127.0.0.1 is default DNS resolver.

Note that some hosting provider like Linode may use a network helper to auto-generate the /etc/resolv.conf file. To change the default DNS resolver, you need to disable that network helper in the hosting control panel.

Update: Later I noticed that the BIND package on Ubuntu 16.04 comes with a Systemd service unit bind9-resolvconf.service, which will help us set the default DNS resolver on Ubuntu server, so you don’t have to do it manually like above. By default, this service is disabled, we need to start it and enable auto-start at boot time.

sudo systemctl start bind9-resolvconf

sudo systemctl enable bind9-resolvconf

Make sure the resolvconf package is installed. Just two lines of commands and BIND will be set as the default DNS resolver on your Ubuntu 16.04 server.
Setting Default DNS Resolver on Client Computers

On Ubuntu desktop, you can follow the above instructions to set the default DNS resolver, but remember to replace 127.0.0.1 with the IP address of BIND server. The steps of setting default DNS resolver on MacOS and Windows can be found on the Internet.
