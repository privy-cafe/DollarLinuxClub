#This repo aim to contain various selections of tools, configurations, sandboxing tools, firewall, softwares to enhance the privacy and security. I do not claim credits for the work all the work,tools,config,softwares,etc here.
If you wish to collaborate join our matrix room. We aim to provide the tools,configurations file and provide ease of deployment      that you and I need to analyze not only prevent potential threats but render them completely useless agains't  the system.
In this rare case obfuscations with anti-pattern  can help us but wait abusing of anti-patterns can be really bad for readability  and auditing.  The goal is to be able to quickly blendin/obfuscate the system to fools potential watchers/listenn ers . It is far from perfect and to be finished. 
Documentation  ---Make sure you do understand what you are doing this is  not a tutorial aimed at novice but a guideline for people with at least one or more years of immersions in a unix like operating system.

    HardeningWalkthrough

    https://wiki.ubuntu.com/CompilerFlags

    http://people.redhat.com/drepper/nonselsec.pdf

    http://www.suse.de/~krahmer/no-nx.pdf

    http://www.neworder.box.sk/newsread.php?newsid=13007

    http://www.hackinthebox.org/modules.php?op=modload&name=News&file=article&sid=15604&mode=thread&order=0&thold=0

    http://www.phrack.org/archives/issues/58/4.txt

    http://insecure.org/sploits/non-executable.stack.problems.html

    http://www.phrack.org/archives/issues/59/9.txt

    http://www.coresecurity.com/files/attachments/Richarte_Stackguard_2002.pdf

    http://www.redhat.com/archives/fedora-tools-list/2004-September/msg00002.html

    http://www.gentoo.org/proj/en/hardened/hardened-toolchain.xml

    https://fedoraproject.org/wiki/Changes/Harden_All_Packages

    http://labs.mwrinfosecurity.com/notices/security_mechanisms_in_linux_environment__part_1___userspace_memory_protection/

    http://labs.mwrinfosecurity.com/notices/assessing_the_tux_strength_part_2_into_the_kernel/
 IMPORTANT!!!!!!!
I'm not responsible , nor Privy services, Digital Gansgter, DGA, PDG if you do not use the content properly
Make sure that you are aware that it is possible that you break your system
You should always make sure that your system is ready, compatible and that those configs/tools/patch are properly deployed

I do not Own everything in this repository, all credits goes to their original writers
I will start writing several bash scripts/.toml files to automate specific setup maybe at some point I will have enough scripts to consider writing a frontend to execute/manage/remove those.
# DollarLinuxClub is slowly progressing, I did few succesfull build based upon different debian based distro such as devuan, miyoLinux(MakeItYourOwn), mx/AntiX and DemonLinux. I was thinking about making those images availables but they are slightly bloated and unstable. Let me know. 
#9999
9999^ kernel, firmware and headers aim to render any kind of fingerprinting imposible and harden the kernel with various patchset. Do not try to install it inside vmware/virtual box it simply won't work since those relies on identifying the cpu ,# of cores etc, which could potentially build  a

#Dappersec  patchset is a originally a RHEL Based patchset(Fedora) ##Ported to debian it does content better patch and desktop integration ( break less stuff ) than latest patch grsec released and the unofficial one.

**Debian Security Advisories(DSA)**
 https://www.debian.org/doc/manuals/securing-debian-howto/ch7.en.html


	PROCEED AT YOUR OWN RISK !! 




Security, what is security ???? 

# Analyze the Threat model

Always ask yourself questions when you are approaching a system to secure.
Even if those question does look and sound stupid, narrowing it down to it most simplistic form is very important.

By narrowing down your scopes and needs , you will avoid a lot's of mistakes.
    
- [ ] Why do you want to secure your server & services ?
- [ ] How much security do you want or not want?
- [ ] How much devices,apps,softwares,database do you need to secure?
- [ ] How much convenience are you willing to compromise for security, people tend to prefer convenience over security.
- [ ] What are the threats you want to protect against? 
- [ ] What are the specifics to your situation? 
- [ ] Do you think physical access to your server/network a possible attack vector?
- [ ] Do you need to deal with known vulnerables hardwares,softwares,libraries ?
- [ ] How are you hosting it, Is it accessible from public ? 
- [ ] Do you have a way of recovering if your security implementation locks you out of your own server? if you disabled root login or password protected GRUB and deleted your SSH pub key.

# **Linux Files Hierarchy** : 

- [ ] Knowing your system is the  most important part. Security is not a software,services nor a patch
- [ ] It is a constant efforts and in depth knowledge of your system and which services run, which ports are used list goes on....
		

**UEFI Secure Boot*
*
Secure Boot is a feature enabled on most PCs that prevents loading unsigned code, protecting against some kinds of bootkit and rootkit.

Debian can now be installed and run on most PCs with Secure Boot enabled.

It is possible to enable Secure Boot on a system that has an existing Debian installation, if it already boots using UEFI. Before doing this, it's necessary to install shim-signed, grub-efi-amd64-signed or grub-efi-ia32-signed, and a Linux kernel package from buster.

Some features of GRUB and Linux are restricted in Secure Boot mode, to prevent modifications to their code.




Linux kernel and its related files are in /boot directory which is by default as read-write. Changing it to read-only reduces the risk of unauthorized modification of critical boot files. We need to edit /etc/fstab file and insert the line below<

It is important to mount couple partitions with specific mount options and their own partitions
A good example would be the /tmp partition which is often used for privilege escalations 
systems should be separated into different partitions for this will prevent lot's of unwanted executions and manipulations

     /
     /boot
     /usr
     /home
     /tmp
     /var
     /opt
	

* LABEL=/boot     /boot     ext2     defaults,ro     1 2

proc     /proc     proc     defaults,hidepid=2     0     0         # added by unknown on 2019-07-06 @ 06:49:51

***Linux Filesystem Permissions***
 ***Make a backup of fstab and apply secure setting for proc and others***

    sudo cp --preserve /etc/fstab /etc/fstab.$(date +"%Y%m%d%H%M%S")
echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/fstab

dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000

mkdir /tmpbackup
      cp -Rpf /tmp /tmpbackup
      mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
      chmod 1777 /tmp
      cp -Rpf /tmpbackup/* /tmp/
      rm -rf /tmpbackup
      echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
      sudo mount -o remount /tmp
      echo "/dev/sda4   /tmp   tmpfs  loop,nosuid,noexec,rw  0 0 "


**Optional hardening of APT**

#All methods provided by APT (e.g. http, and https) except for cdrom, gpgv, and rsh can make use of seccomp-BPF sandboxing as #supplied by the Linux kernel to restrict the list of allowed system calls, and trap all others with a SIGSYS signal. This #sandboxing is currently opt-in and needs to be enabled with:

      APT::Sandbox::Seccomp is a boolean to turn it on/off
    

**Two options can be used to configure this further:**

      APT::Sandbox::Seccomp::Trap is a list of names of more syscalls to trap
      APT::Sandbox::Seccomp::Allow is a list of names of more syscalls to allow
    


# Make sure sensitives files are owned by root and with the rights permissions

```
chmod o= /etc/ftpusers 
chmod o= /etc/group 
chmod o= /etc/hosts
chmod o= /etc/hosts.allow 
chmod o= /etc/hosts.equiv
chmod o= /etc/hosts.lpd 
chmod o= /etc/inetd.conf
chmod o= /etc/login.access 
chmod o= /etc/login.conf 
chmod o= /etc/newsyslog.conf
chmod o= /etc/rc.conf 
chmod o= /etc/ssh/sshd_config 
chmod o= /etc/sysctl.conf
chmod o= /etc/syslog.conf 
chmod o= /etc/ttys 
chmod o= /etc/fstab
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/grub.conf
chown root:root /etc/fstab
chmod og-rwx /etc/grub.conf
chmod 710 /root "or" chmod 700 /root
chmod o= /var/log 
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/gshadow		
chmod 700 /var/log/audit
chmod 740 /etc/rc.d/init.d/iptables
chmod 740 /sbin/iptables
chmod 600 /etc/rsyslog.conf
chmod 640 /etc/security/access.conf
chmod 600 /etc/sysctl.conf
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
```
````
Only root account have UID 0 with full permissions to access the system. Type the following command to display all accounts with UID set to 0:
# awk -F: '($3 == "0") {print}' /etc/passwd



#See all set user id files:
find / -perm +4000
# See all group id files
find / -perm +2000
# Or combine both in a single command
find / \( -perm -4000 -o -perm -2000 \) -print
find / -path -prune -o -type f -perm +6000 -ls


find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
 echo 'install usb-storage /bin/true' * *  /etc/modprobe.d/disable-usb-storage.conf
# echo "blacklist firewire-core" * *  /etc/modprobe.d/firewire.conf
# echo "blacklist thunderbolt" * *  /etc/modprobe.d/thunderbolt.conf
sudo dpkg-statoverride --update --add root sudo 4750 /bin/su
		
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" } ' >> /etc/audit/audit.rules

echo " " >> /etc/audit/audit.rules
echo "#End of Audit Rules" >> /etc/audit/audit.rules
echo "-e 2" >>/etc/audit/audit.rules

cp /etc/audit/audit.rules /etc/audit/rules.d/audit.rules

chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg


chown root:root /etc/cron*
chmod og-rwx /etc/cron*

#5.1.8 Ensure at/cron is restricted to authorized users (Scored)

touch /etc/cron.allow
touch /etc/at.allow

chmod og-rwx /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod -R g-wx,o-rwx /var/log/*



chown root:root /etc/cron*```

Afters system, files and other permissions we will edit out kernel setting in `/etc/sysctl.conf`

```
fs.file-max = 65535 		
fs.protected_hardlinks = 1 		
fs.protected_symlinks = 1 		
fs.suid_dumpable = 0 		
kernel.core_uses_pid = 1 		
kernel.ctrl-alt-del = 0 		
kernel.kptr_restrict = 2 		
kernel.maps_protect = 1 		
kernel.msgmax = 65535 		
kernel.msgmnb = 65535 		
kernel.pid_max = 65535 	
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 2
kernel.unprivileged_userns_clone=1
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control=htcp
kernel.maps_protect = 1
kernel.ctrl-alt-del = 0
fs.file-max = 100000
net.core.netdev_max_backlog = 100000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000
net.core.somaxconn = 1024
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 10
vm.overcommit_ratio = 50
vm.overcommit_memory = 0
vm.mmap_min_addr = 4096
vm.min_free_kbytes = 65535
net.unix.max_dgram_qlen = 50
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
vm.dirty_background_bytes = 4194304
vm.dirty_bytes = 4194304
kernel.kptr_restrict = 2
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_challenge_ack_limit = 1000000
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_synack_retries = 2
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
fs.file-max = 65535
#Allow for more PIDs 
kernel.pid_max = 65536
#Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_orphan_retries = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.conf.lo.log_martians = 0
net.ipv4.conf.eth0.rp_filter = 1
net.ipv4.conf.eth0.log_martians = 0
kernel.unprivileged_userns_clone = 1

net.core.bpf_jit_harden=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled=1
net.ipv4.ip_default_ttl = 255
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

kernel.randomize_va_space = 2 		
kernel.shmall = 268435456 		
kernel.shmmax = 268435456 		
kernel.sysrq = 0 		
net.core.default_qdisc = fq 		
net.core.dev_weight = 64 		
net.core.netdev_max_backlog = 16384 		
net.core.optmem_max = 65535 		
net.core.rmem_default = 262144 		
net.core.rmem_max = 16777216 		
net.core.somaxconn = 32768 		
net.core.wmem_default = 262144 		
net.core.wmem_max = 16777216 		
net.ipv4.conf.all.accept_redirects = 0 		
net.ipv4.conf.all.accept_source_route = 0 		
net.ipv4.conf.all.bootp_relay = 0 		
net.ipv4.conf.all.forwarding = 0 		
net.ipv4.conf.all.log_martians = 1 		
net.ipv4.conf.all.proxy_arp = 0 		
net.ipv4.conf.all.rp_filter = 1 		
net.ipv4.conf.all.secure_redirects = 0 		
net.ipv4.conf.all.send_redirects = 0 		
net.ipv4.conf.default.accept_redirects = 0 		
net.ipv4.conf.default.accept_source_route = 0 		
net.ipv4.conf.default.forwarding = 0 		
net.ipv4.conf.default.log_martians = 1 		
net.ipv4.conf.default.rp_filter = 1 		
net.ipv4.conf.default.secure_redirects = 0 		
net.ipv4.conf.default.send_redirects = 0 		
net.ipv4.conf.eth0.accept_redirects = 0 	change eth0 to your network interface 	
net.ipv4.conf.eth0.accept_source_route = 0 	change eth0 to your network interface 	
net.ipv4.conf.eth0.log_martians = 0 	change eth0 to your network interface 	
net.ipv4.conf.eth0.rp_filter = 1 	change eth0 to your network interface 	
net.ipv4.conf.lo.accept_redirects = 0 		
net.ipv4.conf.lo.accept_source_route = 0 		
net.ipv4.conf.lo.log_martians = 0 		
net.ipv4.conf.lo.rp_filter = 1 		
net.ipv4.icmp_echo_ignore_all = 1 		
net.ipv4.icmp_echo_ignore_broadcasts = 1 		
net.ipv4.icmp_ignore_bogus_error_responses = 1 		
net.ipv4.ip_forward = 0 		
net.ipv4.ip_local_port_range = 2000 65000 		
net.ipv4.ipfrag_high_thresh = 262144 		
net.ipv4.ipfrag_low_thresh = 196608 		
net.ipv4.neigh.default.gc_interval = 30 		
net.ipv4.neigh.default.gc_thresh1 = 32 		
net.ipv4.neigh.default.gc_thresh2 = 1024 		
net.ipv4.neigh.default.gc_thresh3 = 2048 		
net.ipv4.neigh.default.proxy_qlen = 96 		
net.ipv4.neigh.default.unres_qlen = 6 		
net.ipv4.route.flush = 1 		
net.ipv4.tcp_congestion_control = htcp 		
net.ipv4.tcp_ecn = 1 		
net.ipv4.tcp_fastopen = 3 		
net.ipv4.tcp_fin_timeout = 15 		
net.ipv4.tcp_keepalive_intvl = 15 		
net.ipv4.tcp_keepalive_probes = 5 		
net.ipv4.tcp_keepalive_time = 1800 		
net.ipv4.tcp_max_orphans = 16384 		
net.ipv4.tcp_max_syn_backlog = 2048 		
net.ipv4.tcp_max_tw_buckets = 1440000 		
net.ipv4.tcp_moderate_rcvbuf = 1 		
net.ipv4.tcp_no_metrics_save = 1 		
net.ipv4.tcp_orphan_retries = 0 		
net.ipv4.tcp_reordering = 3 		
net.ipv4.tcp_retries1 = 3 		
net.ipv4.tcp_retries2 = 15 		
net.ipv4.tcp_rfc1337 = 1 		
net.ipv4.tcp_rmem = 8192 87380 16777216 		
net.ipv4.tcp_sack = 0 		
net.ipv4.tcp_slow_start_after_idle = 0 		
net.ipv4.tcp_syn_retries = 5 		
net.ipv4.tcp_synack_retries = 2 		
net.ipv4.tcp_syncookies = 1 		
net.ipv4.tcp_timestamps = 1 		
net.ipv4.tcp_tw_recycle = 0 		
net.ipv4.tcp_tw_reuse = 1 		
net.ipv4.tcp_window_scaling = 0 		
net.ipv4.tcp_wmem = 8192 65536 16777216 		
net.ipv4.udp_rmem_min = 16384 		
net.ipv4.udp_wmem_min = 16384 		
net.ipv6.conf.all.accept_ra=0 		
net.ipv6.conf.all.accept_redirects = 0 		
net.ipv6.conf.all.accept_source_route = 0 		
net.ipv6.conf.all.autoconf = 0 		
net.ipv6.conf.all.forwarding = 0 		
net.ipv6.conf.default.accept_ra_defrtr = 0 		
net.ipv6.conf.default.accept_ra_pinfo = 0 		
net.ipv6.conf.default.accept_ra_rtr_pref = 0 		
net.ipv6.conf.default.accept_ra=0 		
net.ipv6.conf.default.accept_redirects = 0 		
net.ipv6.conf.default.accept_source_route = 0 		
net.ipv6.conf.default.autoconf = 0 		
net.ipv6.conf.default.dad_transmits = 0 		
net.ipv6.conf.default.forwarding = 0 		
net.ipv6.conf.default.max_addresses = 1 		
net.ipv6.conf.default.router_solicitations = 0 		
net.ipv6.conf.eth0.accept_ra=0 	change eth0 to your network interface 	
net.ipv6.conf.eth0.autoconf = 0 	change eth0 to your network interface 	
net.ipv6.ip6frag_high_thresh = 262144 		
net.ipv6.ip6frag_low_thresh = 196608 		
net.ipv6.route.flush = 1 		
net.unix.max_dgram_qlen = 50 		
vm.dirty_background_ratio = 5 		
vm.dirty_ratio = 30 		t
vm.min_free_kbytes = 65535 		
vm.mmap_min_addr = 4096 		
vm.overcommit_ratio = 50 		
vm.swappiness = 10 		


#profile mask setting
sudo cp --preserve /etc/profile /etc/profile.$(date +"%Y%m%d%H%M%S")
sudo cp --preserve /etc/bash.bashrc /etc/bash.bashrc.$(date +"%Y%m%d%H%M%S")
sudo cp --preserve /etc/login.defs /etc/login.defs.$(date +"%Y%m%d%H%M%S")
sudo cp --preserve /root/.bashrc /root/.bashrc.$(date +"%Y%m%d%H%M%S")
echo -e "\numask 0027         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/profile /etc/bash.bashrc
echo -e "\nUMASK 0027         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/login.defs
echo -e "\numask 0077         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /root/.bashrc



Install ntp if you need it.

On Debian based systems:

sudo apt install ntp

Make a backup of the NTP client's configuration file /etc/ntp.conf:

sudo cp --preserve /etc/ntp.conf /etc/ntp.conf.$(date +"%Y%m%d%H%M%S")


sudo sed -i -r -e "s/^((server|pool).*)/# \1         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/ntp.conf
echo -e "\npool pool.ntp.org iburst         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/ntp.conf

sudo service ntp restart

# Configure TimeZone
config_timezone(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m We will now Configure the TimeZone"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
   say_done
}


#Ensure system accounts are non-login 

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
    usermod -s /usr/sbin/nologin $user
  fi
  fi
done

#Ensure default group for the root account is GID 0 

usermod -g 0 root

#Ensure default user umask is 027 or more restrictive 

sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc
`
# Create an Ed25519 key with ssh-keygen instead of using RSA :

```
ssh-keygen -t ed25519
sudo groupadd sudousers
sudo groupadd jailedusers
sudo groupadd sshusers
sudo usermod -a -G sshusers user1
sudo cp --preserve /etc/sudoers /etc/sudoers.$(date +"%Y%m%d%H%M%S")
sudo visudo
sudo cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
sudo sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config
%sudousers   ALL=(ALL:ALL) ALL
```

 echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #Remove AT and Restrict Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " Securing Cron "
    spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
    echo -n " Do you want to Disable USB Support for this Server? (y/n): " ; read usb_answer
    if [ "$usb_answer" == "y" ]; then
       echo ""
       echo "Disabling USB Support"
       spinner
       echo "blacklist usb-storage" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u



Open `/etc/pam.d/system-auth` using any text editor and add the following line:

`/lib/security/$ISA/pam_cracklib.so retry=3 minlen=8 lcredit=-1 ucredit=-2 dcredit=-2 ocredit=-1`

* Linux will hash the password to avoid saving it in cleartext so, you need to make sure to define a secure password hashing algorithm SHA512.

* Another interesting functionality is to lock the account after five failed attempts. To make this happen, you need to open the file “/etc/pam.d/password-auth” and add the following lines:

```
auth required pam_env.so 
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=604800 
auth [success=1 default=bad] pam_unix.so 
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=604800 
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=604800 
auth required pam_deny.so
```

* We’re not done yet; one additional step is needed. Open the file “/etc/pam.d/system-auth” and make sure you have the following lines added:

```
auth required pam_env.so 
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=604800 
auth [success=1 default=bad] pam_unix.so 
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=604800 
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=604800 
auth required pam_deny.so
```

* After five failed attempts, only an administrator can unlock the account by using the following command:

# `/usr/sbin/faillock --user <userlocked*   --reset`



#!/bin/bash 
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do
if [ $user != "root" ] 
then 
/usr/sbin/usermod -L $user 
if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ] 
then /usr/sbin/usermod -s /sbin/nologin $user 
fi 
fi 
done



`nano /etc/modprobe.d/blacklist.conf`

* When the file opens, then add the following line at the end of the file (save and close):

`blacklist usb_storage`

* After this, open the rc.local file:

`nano /etc/rc.local`

* Finally, add the following two lines:

```
modprobe -r usb_storage
exit 0
```


# Removing root user access, tty and login capabilities.

```
	sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
	sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
	
	#Default /etc/passwd for root

	root:x:0:0:root:/root:/bin/bash
```

* After disabling root login

`root:x:0:0:root:/root:/sbin/nologin`

* Can be a solutions combined with locking + chattr

```
passwd -l  root
sed -i -e 's/^root::/root:!:/' /etc/shadow
```

```
echo *  /etc/secu
	[atmos@privy ~]$ sudo reboot
	[sudo] password for atmos:
	atmosis not in the sudoers file.  This incident will be reported.
```

* However after running ‘visudo’ and editing the sudoers file as below, this becomes possible.

```
atmos     ALL=/usr/sbin/reboot
retty

usermod -aG wheel $USER
sed -i '/%wheel/s/^# //' /etc/sudoers
or

mkdir -p ~/.ssh && sudo chmod -R 700 ~/.ssh/

From your local computer:

scp ~/.ssh/id_rsa.pub example_user@203.0.113.10:~/.ssh/authorized_keys

mkdir ~/.ssh; nano ~/.ssh/authorized_keys
mkdir -p ~/.ssh && sudo chmod -R 700 ~/.ssh/
```

$ sudo iptables --flush  # start again
$  do iptables --new-chain RATE-LIMIT
$ sudo iptables --append RATE-LIMIT \
    --match hashlimit \
    --hashlimit-upto 50/sec \
    --hashlimit-burst 20 \
    --hashlimit-name conn_rate_limit \
    --jump ACCEPT
$ sudo iptables --append RATE-LIMIT --jump DROP



# visudo can be configured to use an editor other than vi if desired. Edit /etc/sudoers using visudo:

```
  visudo /etc/sudoers
  Uncomment to allow members of group wheel to execute any command
  %wheel ALL=(ALL) ALL
```

* Lock the root account

The output of passwd -S root reveals how P is changed to L:
```
  $ sudo passwd -S root
  root P 03/27/2016 0 99999 7 -1
```

```  
  $ sudo passwd -dl root
  passwd: password expiry information changed.
```

```
  $ sudo passwd -S root
  root L 03/27/2016 0 99999 7 -1
```

* Set the root account shell to bash, the status can be viewed in `/etc/passwd`:

  `$ sudo usermod --shell /bin/bash root`

Set up sulogin for Grub rescue mode to allow operation without a root account password

Configure runit to use the sulogin -e option. Create the file /etc/sv/sulogin/conf with this content:

  OPTS="-e"

The conf file will be read by /etc/sv/sulogin/run.

Or if OPTS is not supported in the run file, edit the last line of /etc/sv/sulogin/run to this (although it will be overwritten on subsequent updates of runit and will need to be edited again):

  exec setsid sulogin -e < $tty * $tty 2* &1

This means if there is no root password, rescue mode boots to a root terminal which doesn't require a password. This is potentially insecure if the terminal can be physically accessed by others, although there are numerous other security issues in that situation. If a root password is set, then it will still be requested.

The root default environment in rescue mode could be lacking some elements for normal operation as displayed by the env command:

  $ env
  SHELL=/bin/bash
  USER=root
  PATH=/usr/bin:/usr/sbin
  PWD=/root
  SHLVL=1
  HOME=/root
  LOGNAME=root
  _=/usr/bin/env

This can be amended as desired by creating or editing /root/.bashrc, e.g.:

  # .bashrc

  # If not running interactively, don't do anything
  [[ $- != *i* ]] && return

  alias ls='ls --color=auto'
  PS1='[\u@\h \W]\$ '
  export PAGER=less
  export EDITOR=nano
  export TERM=xterm
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin

 find world writables files on the server

find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
files without owner
find /dir -xdev \( -nouser -o -nogroup \) -print

lockdown cronjob 

echo ALL * * /etc/cron.deny

#Make a backup of OpenSSH server's configuration file /etc/ssh/sshd_config and remove comments to make it easier to read:

    sudo cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +"%Y%m%d%H%M%S")
    sudo sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config


Create a group:

sudo groupadd sshusers

Add account(s) to the group:

sudo usermod -a -G sshusers $USER

port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
logingracetime 30
x11displayoffset 10
maxauthtries 2
maxsessions 2
clientaliveinterval 300
clientalivecountmax 0
streamlocalbindmask 0177
permitrootlogin no
ignorerhosts yes
ignoreuserknownhosts no
hostbasedauthentication no
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# LogLevel VERBOSE logs user's key fingerprint on login. Needed to have a clear audit track of which key was using to log in.
LogLevel VERBOSE

# Use kernel sandbox mechanisms where possible in unprivileged processes
# Systrace on OpenBSD, Seccomp on Linux, seatbelt on MacOSX/Darwin, rlimit elsewhere.
# Note: This setting is deprecated in OpenSSH 7.5 (https://www.openssh.com/txt/release-7.5)
UsePrivilegeSeparation sandbox

########################################################################################################
# end settings from https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67 as of 2019-01-01
########################################################################################################

# don't let users set environment variables
PermitUserEnvironment no

# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
Subsystem sftp  internal-sftp -f AUTHPRIV -l INFO

# only use the newer, more secure protocol
Protocol 2

# disable X11 forwarding as X11 is very insecure
# you really shouldn't be running X on a server anyway
X11Forwarding no

# disable port forwarding
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# don't allow login if the account has an empty password
PermitEmptyPasswords no

# ignore .rhosts and .shosts
IgnoreRhosts yes

# verify hostname matches IP
UseDNS no

Compression no
TCPKeepAlive no
AllowAgentForwarding no
PermitRootLogin no

# don't allow .rhosts or /etc/hosts.equiv
HostbasedAuthentication no
subsystem sftp internal-sftp -f AUTHPRIV -l INFO
maxstartups 2:30:2
permittunnel no
ipqos lowdelay throughput
rekeylimit 0 0
permitopen any

sudo cp --preserve /etc/ssh/moduli /etc/ssh/moduli.$(date +"%Y%m%d%H%M%S")

Remove short moduli:

sudo awk '$5 * = 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli

sudo sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")\n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")/" /etc/pam.d/common-password


sudo psad -R
sudo psad --sig-update
sudo psad -H
sudo cp --preserve /etc/psad/psad.conf /etc/psad/psad.conf.$(date +"%Y%m%d%H%M%S")
sudo apt install aide
sudo cp -p /etc/default/aide /etc/default/aide.$(date +"%Y%m%d%H%M%S")
sudo cp -pr /etc/aide /etc/aide.$(date +"%Y%m%d%H%M%S")
sudo aideinit
sudo aide.wrapper --check


# if you are not sure the change worked , verify the configuration with this
sudo touch /etc/test.sh
sudo touch /root/test.sh
sudo aide.wrapper --check
sudo rm /etc/test.sh
sudo rm /root/test.sh
sudo aideinit -y -f

    	

46		

Ensure the following are set in /etc/pam.d/other:

    auth  required pam_deny.so
    auth   required pam_warn.so
    account  required pam_deny.so
    account  required pam_warn.so
    password  required pam_deny.so
    password  required pam_warn.so
    session  required pam_deny.so
    session  required pam_warn.so
    session  required pam_deny.so

Warn will report alerts to syslog.

To require strong passwords, in compliance with section 5.18 of the Information Resources Use and Security Policy:

For RHEL 6:

In /etc/pam.d/system-auth, add or change the file as required to read:
password   required     pam_cracklib.so retry=3 difok=5 minlen=8 lcredit=-1 dcredit=-1 ocredit=-1
password   sufficient   pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=10
password   required     pam_deny.so
password   required     pam_warn.so

 

For RHEL 7:

In /etc/security/pwquality.conf, add:
difok = 5
minlen = 8
minclass = 1
maxrepeat = 0
maxclassrepeat = 0
lcredit = -1
ucredit = 0
dcredit = -1
ocredit = -1
gecoscheck = 1

 

In /etc/pam.d/system-auth, add or change the file as required to read:
password    required    pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient  pam_unix.so sha512 shadow try_first_pass use_authtok remember=10
password    required    pam_deny.so


kernel hardening 





Make sure no files have no owner specified

    find /dir -xdev \( -nouser -o -nogroup \) -print

Verify no files are world-writeable

    find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print

/etc/pam.d/system-login

auth optional pam_faildelay.so delay=4000000


/etc/pam.d/system-login

auth required pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog



/etc/security/limits.conf
* soft nproc 100
* hard nproc 200
* soft nofile 100000
* hard nofile 100000


if you added hardening to /proc in /etc/fstab For user sessions to work correctly, an exception needs to be added for systemd-logind:

/etc/systemd/system/systemd-logind.service.d/hidepid.conf

[Service]
SupplementaryGroups=proc


# vim: filetype=conf:




If you are using Bash or Zsh, you can set TMOUT for an automatic logout from shells after a timeout.

For example, the following will automatically log out from virtual consoles (but not terminal emulators in X11):

/etc/profile.d/shell-timeout.sh

TMOUT="$(( 60*10 ))";
[ -z "$DISPLAY" ] && export TMOUT;
case $( /usr/bin/tty ) in
	/dev/tty[0-9]*) export TMOUT;;
esac

If you really want EVERY Bash/Zsh prompt (even within X) to timeout, use:

$ export TMOUT="$(( 60*10 ))";



Enter the chroot and create a user:

 sudo chroot ~/chroot
 useradd -G audio,video <username* 
 exit

Then run Skype as your newly created user:

 sudo chroot ~/chroot /bin/su - <username*  -c /usr/bin/skype
:::::::::::::

bash

!/bin/bash CHROOT_PATH="/home/$USER/chroot" cd $CHROOT_PATH mount | grep $CHROOT_PATH/dev || sudo mount --bind /dev dev mount | grep $CHROOT_PATH/sys || sudo mount --bind /sys sys mount | grep $CHROOT_PATH/proc || sudo mount -t proc proc proc cp /etc/resolv.conf etc sudo chroot --userspec=$USER:users . /bin/bash echo "You must manually unmount $CHROOT_PATH/dev, $CHROOT_PATH/sys, $CHROOT_PATH/proc." 

# remove some stupid / dangerous key bindings




systemctl , kernel configuration
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 2
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control=htcp
kernel.maps_protect = 1
kernel.ctrl-alt-del = 0

fs.file-max = 100000
net.core.netdev_max_backlog = 100000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000
net.core.somaxconn = 1024
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 10
vm.overcommit_ratio = 50
vm.overcommit_memory = 0
vm.mmap_min_addr = 4096
vm.min_free_kbytes = 65535
net.unix.max_dgram_qlen = 50
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
vm.dirty_background_bytes = 4194304
vm.dirty_bytes = 4194304
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_challenge_ack_limit = 1000000
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_synack_retries = 2
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.accept_ra_rtr_pref = 0
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0

# increase system file descriptor limit    
fs.file-max = 65535
 
#Allow for more PIDs 
kernel.pid_max = 65536
 
#Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000

net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_orphan_retries = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.conf.lo.log_martians = 0
net.ipv4.conf.eth0.rp_filter = 1
net.ipv4.conf.eth0.log_martians = 0



 change /etc/rc.securelevel so that the securelevel is 2. Then go through your files and chflags -R schg them. I would do this for most of /etc, all of /bin,/sbin,/usr,/bsd,/boot and sappend on some other files/directories like /root and /altroot and on key logs in /var/log. You may need to hand-tune log rotation. 
d.) use TCP Wrappers (/etc/hosts.allow,/etc/hosts.deny). /etc/hosts.deny should read: ALL: ALL. Then figure out what you will allow. Also consider turning off inetd entirely by putting inetd_flags=NO in /etc/rc.conf.local There's a way to boobytrap TCP Wrappers that's explained in the man page, but I haven't done it yet.

e.) use mtree -cK sha1digest *  snapshot_of_filesystem__on_date once you have everything set up. Then cksum -a sha1 that file. ...as explained in the mtree man page. Make it a cron job, and write a script to diff your snapshots. Also keep the main snapshot offline. This can alert you if key files have been tampered with or accessed by someone other than you or your machine. So it's sort of like a host-based IDS.

f.) deny root login and port forwarding/X11 forwarding in /etc/ssh/sshd_config, especially if you are running sshd!

g.) in /etc/fstab mount /usr ro, and /tmp,/var,/home with noexec Consider whether your user can log into an rksh shell.

cat /dev/srandom | tr -dc [:print:] | fold -w PWD_LENGTH | head -n NUM_OF_PWDS



L2 Tunnel bash

#!/bin/bash

# prereqs:
# remote host's sshd_config must have "PermitRootLogin=no", "AllowUsers user", and "PermitTunnel=yes"
# "tunctl", in debians it is found in uml-utils, redhats another (dont remember but "yum provides tunctl" must tell)
# remote user must be able to sudo-as-root
# can opt by routing as in this case or soft bridge with brctl and you get full remote ethernet segment membership :D
# that last i think i'll implement later as an option
# other stuff to do is error checking, etcetc, this is just as came from the oven

userhost='user@host'
sshflags='-Ap 2020 -i /path/to/some/authkey'
vpn='10.0.0.0/24'
rnet=192.168.40.0/24

# START VPN
if [ "$1" == "start" ]; then
echo setting up local tap ...
ltap=$(tunctl -b)
ifconfig $ltap ${vpn%%?/*}2/${vpn##*/} up

echo setting remote configuration and enabling root login ...
rtap="ssh $sshflags $userhost sudo 'bash -c \"rtap=\\\$(tunctl -b); echo \\\$rtap; ifconfig \\\$rtap ${vpn%%?/*}1/${vpn##*/} up; iptables -A FORWARD -i \\\$rtap -j ACCEPT; iptables -A FORWARD -o \\\$rtap -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -s ${vpn%%?/*}2 -j SNAT --to \\\$(ip r | grep $rnet | sed \\\"s/^.*src \\\(.*\\\$\\\)/\1/g\\\"); sed -i -e \\\"s/\\\(PermitRootLogin\\\).*\\\$/\1 without-password/g\\\" -e \\\"s/\\\(AllowUsers.*\\\)\\\$/\1 root/g\\\" /etc/ssh/sshd_config; /usr/sbin/sshd -t\"'"
rtap=$(sh -c "$rtap")

echo setting up local routes ...
# since my ISP sucks with transparent filters (i can't opt for another where i live), i'll just use my work net as gateway
ip r a $(ip r | grep default | sed "s/default/${userhost##*@}/")
ip r c default via ${vpn%%?/*}1 dev $ltap

echo bringing up the tunnel and disabling root login ...
ssh $sshflags -f -w ${ltap##tap}:${rtap##tap} -o Tunnel=ethernet -o ControlMaster=yes -o ControlPath=/root/.ssh/vpn-$userhost-l$ltap-r$rtap root@${userhost##*@} bash -c "\"sed -i -e 's/\(PermitRootLogin\).*\$/\1 no/g' -e 's/\(AllowUsers.*\) root\$/\1/g' /etc/ssh/sshd_config; /usr/sbin/sshd -t\""

echo connected.

# STOP VPN
elif [ "$1" == "stop" ]; then
echo searching control socket and determining configuration ...
controlpath=$(echo /root/.ssh/vpn-$userhost*)
ltap=${controlpath%%-rtap*} && ltap=tap${ltap##*-ltap}
rtap=${controlpath##*rtap} && rtap=tap${rtap%%-*}

echo bringing the tunnel down ...
ssh $sshflags -o ControlPath=$controlpath -O exit $userhost

echo restoring local routes ...
ip r c default $(ip r | grep ${userhost##*@} | sed "s/${userhost##*@}\(.*$\)/\1/g")
ip r d ${userhost##*@}

echo restoring remote configuration ...
sh -c "ssh $sshflags $userhost sudo 'bash -c \"tunctl -d $rtap; iptables -D FORWARD -i $rtap -j ACCEPT; iptables -D FORWARD -o $rtap -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -s ${vpn%%?/*}2 -j SNAT --to \$(ip r | grep $rnet | sed \"s/^.*src \(.*\$\)/\1/g\")\"'"

echo deleting local tap ...
tunctl -d $ltap

echo disconnected.
fi


    root@mine:/# apt-get install nbd-server

    Now we'll create a file to export:

    root@mine:/# modprobe nbd
    root@mine:/# mkdir -p /home/exported
    root@mine:/# dd if=/dev/zero of=/home/exported/trial.img count=256 bs=1024k
    root@mine:/# mkfs.ext3 /home/exported/trial.img

    Unmount the volume:

    root@yours:/# umount /mnt/remote 

    Now try mounting it back upon the server, to make sure that those files have persisted and been created as we expect:

    root@vain:~#  nbd-client 127.0.0.1 1234 /dev/nbd0
    root@vain:~# mkdir /tmp/foo
    root@vain:~#  mount /dev/nbd0 /tmp/foo
    root@vain:~#  ls /tmp/foo/
    1    14  2   25  30  36  41  47  52  58  63  69  74  8   85  90  96
    10   15  20  26  31  37  42  48  53  59  64  7   75  80  86  91  97
    100  16  21  27  32  38  43  49  54  6   65  70  76  81  87  92  98
    11   17  22  28  33  39  44  5   55  60  66  71  77  82  88  93  99
    12   18  23  29  34  4   45  50  56  61  67  72  78  83  89  94  
    13   19  24  3   35  40  46  51  57  62  68  73  79  84  9   95  lost+found

    Fun, huh?

Working With Xen

    I spent a while trying to get this working with Xen, but only found success when using the /dev/nbdN devices.

    For this to work I had to use the following Xen configuration, which is less than ideal:

    disk        = [ 'phy:vain-vol/etch-builder.my.flat-disk,sda1,w', 
                    'phy:vain-vol/etch-builder.my.flat-swap,sda2,w',
                    'phy:/dev/nbd0,sda3,w' ]

First, Restrict Core Dumps by:

    Adding hard core 0 to the “/etc/security/limits.conf” file
    Adding fs.suid_dumpable = 0 to the “/etc/sysctl.conf” file

Second, configure Exec Shield by:

    Adding kernel.exec-shield = 1 to the “/etc/sysctl.conf” file

Third, enable randomized Virtual Memory Region Placement by:

    Adding kernel.randomize_va_space = 2 to the “/etc/sysctl.conf” file


