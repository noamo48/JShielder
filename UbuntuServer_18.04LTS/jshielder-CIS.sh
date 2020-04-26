#!/bin/bash

# JShielder v2.4
# CIS Hardening Script for Ubuntu Server 16.04 LTS
#
# Jason Soto
# www.jasonsoto.com
# www.jsitech-sec.com
# Twitter = @JsiTech

source helpers.sh

##############################################################################################################

f_banner(){
echo
echo "

     ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ███████╗██████╗
     ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗
     ██║███████╗███████║██║█████╗  ██║     ██║  ██║█████╗  ██████╔╝
██   ██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔══╝  ██╔══██╗
╚█████╔╝███████║██║  ██║██║███████╗███████╗██████╔╝███████╗██║  ██║
╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                              
CIS Benchmark Hardening
For Ubuntu Server 16.04 LTS
By Jason Soto "
echo
echo

}


##############################################################################################################

# Check if running with root User

clear
f_banner


check_root() {
if [ $EUID -ne 0 ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
else
      clear
      f_banner
      cat templates/texts/welcome-CIS
fi
}

##############################################################################################################

check_root
say_continue

echo -e ""
echo -e "Disabling unused filesystems"
spinner
sleep 2

#1.1.1.1 Ensure Mounting of cramfs is disabled (Scored)

echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)

echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)

echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)

echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)

echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)

echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)

echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)

echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.2 Ensure /tmp is configured (Scored)
#1.1.3 Ensure nodev option set on /tmp partition (Scored)
#1.1.4 Ensure nosuid option set on /tmp partition (Scored)
#1.1.5 Ensure noexec option set on /tmp partition (Scored)
#1.1.6 Ensure separate partition exists for /var (Scored)
#1.1.7 Ensure separate partition exists for /var/tmp (Scored)
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
#1.1.10 Ensure noexec option set on /var/tmp partition (Scored)

#1.1.11 Ensure separate partition exists for /var/log (Scored)
#1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
#1.1.13 Ensure separate partition exists for /home (Scored)
#1.1.14 Ensure nodev option set on /home partition (Scored)
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
#1.1.17 Ensure noexec option set on /dev/shm partition (Scored)

#1.1.18 Ensure nodev option set on removable media partitions (Not Scored)
#1.1.19 Ensure nosuid option set on removable media partitions (Not Scored)
#1.1.20 Ensure noexec option set on removable media partitions (Not Scored)

#1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)

clear
f_banner

echo -e ""
echo -e "Setting Sticky bit on all world-writable directories"
sleep 2
spinner

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

#1.1.22 Disable Automounting (Scored)
#1.1.23 Disable USB Storage (Scored)

#1.2 Configure Software Updates
#1.2.1 Ensure package manager repositories are configured (Not Scored)

#1.2.2 Ensure GPG keys are configured (Not Scored)

#1.3 Configure sudo
#1.3.1 Ensure sudo is installed (Scored)
#1.3.2 Ensure sudo commands use pty (Scored)
#1.3.3 Ensure sudo log file exists (Scored)

#1.4 Filesystem Integrity Checking

#1.4.1 Ensure AIDE is installed (Scored)

clear
f_banner
echo -e ""
echo -e "Installing and configuring AIDE"

DEBIAN_FRONTEND=noninteractive apt-get -yq install nullmailer
DEBIAN_FRONTEND=noninteractive apt-get -yq install aide
aideinit

#1.4.2 Ensure filesystem integrity is regularly checked (Scored)
#1.4.3 Ensure authentication required for single user mode (Scored)

# 1.5 - N/A for cloud environments
#1.5 Secure Boot Settings
#1.5.1 Ensure permissions on bootloader config are configured (Scored)
#1.5.2 Ensure bootloader password is set (Scored)
#1.5.3 Ensure authentication required for single user mode (Scored)
#1.5.4 Ensure interactive boot is not enabled (Not Scored)


#1.6 Additional Process Hardening
#1.6.1 Ensure XD/NX support is enabled (Scored)
#1.6.2 Ensure address space layout randomization (ASLR) is enabled (Scored)
    #already set on sysctl.conf template file
    
#1.6.3 Ensure prelink is disabled (Scored)
    # not installed by default on Clean Ubuntu install, will add condition later on

#1.6.4 Ensure core dumps are restricted (Scored)

echo "* hard core 0" >> /etc/security/limits.conf
cp templates/sysctl-CIS.conf /etc/sysctl.conf
sysctl -e -p

#1.7 Mandatory Access Control
#1.7.1.1 Ensure AppArmor is installed (Scored)
#1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration (Scored).
#1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Scored)
#1.7.1.4 Ensure all AppArmor Profiles are enforcing (Scored)


#1.8 Warning Banners
#1.8.1.1 Ensure message of the day is configured properly (Scored)
#1.8.1.2 Ensure local login warning banner is configured properly (Not Scored)
#1.8.1.3 Ensure remote login warning banner is configured properly (Not Scored)
cat templates/motd-CIS > /etc/motd
cat templates/motd-CIS > /etc/issue
cat templates/motd-CIS > /etc/issue.net

#1.8.1.4 Ensure permissions on /etc/motd are configured (Not Scored)
#1.8.1.5 Ensure permissions on /etc/issue are configured (Scored)
#1.8.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored)

chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644 /etc/motd /etc/issue /etc/issue.net

#1.8.2 Ensure GDM login banner is configured (Scored)
#1.9 Ensure updates, patches, and additional security software are installed (Not Scored)

apt-get -y update
apt-get -y upgrade

############################################################


### NOT ENABLED ON CLEAN INSTALL
## Will configure later on for current install ##


#2 Services
#2.1 inetd Services
#2.1.1 Ensure xinetd is not installed (Scored)
#2.1.2 Ensure openbsd-inetd is not installed (Scored)

##############################################################
#2.2 Special Purpose Services
#2.2.1.1 Ensure time synchronization is in use (Not Scored)
#2.2.1.2 Ensure systemd-timesyncd is configured (Not Scored)
#2.2.1.2 Ensure chrony is configured (Scored)
#2.2.1.3 Ensure ntp is configured (Scored)

#2.2.2 Ensure X Window System is not installed (Scored)
#2.2.3 Ensure Avahi Server is not enabled (Scored)
#2.2.4 Ensure CUPS is not enabled (Scored)
#2.2.5 Ensure DHCP Server is not enabled (Scored)
#2.2.6 Ensure LDAP server is not enabled (Scored)
#2.2.7 Ensure NFS and RPC are not enabled (Scored)
#2.2.8 Ensure DNS Server is not enabled (Scored)
#2.2.9 Ensure FTP Server is not enabled (Scored)
#2.2.10 Ensure HTTP server is not enabled (Scored)
#2.2.11 Ensure email services are not enabled (Scored)
#2.2.12 Ensure Samba is not enabled (Scored)
#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
#2.2.14 Ensure SNMP Server is not enabled (Scored)
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
#2.2.16 Ensure rsync service is not enabled (Scored)
#2.2.17 Ensure NIS Server is not enabled (Scored)
#2.3 Service Clients
#2.3.1 Ensure NIS Client is not installed (Scored)
#2.3.2 Ensure rsh client is not installed (Scored)
#2.3.3 Ensure talk client is not installed (Scored)
#2.3.4 Ensure telnet client is not installed (Scored)

apt-get -y remove telnet

#2.3.5 Ensure LDAP client is not installed (Scored)

#######################################################################

#3 Network Configuration
#3.1 Network Parameters (Host Only)
#3.1.1 Ensure packet redirect sending is disabled (Scored)
#3.1.2 Ensure IP forwarding is disabled (Scored)
#3.2 Network Parameters (Host and Router)
#3.2.1 Ensure source routed packets are not accepted (Scored)
#3.2.2 Ensure ICMP redirects are not accepted (Scored)
#3.2.3 Ensure secure ICMP redirects are not accepted (Scored)
#3.2.4 Ensure suspicious packets are logged (Scored)
#3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
#3.2.6 Ensure bogus ICMP responses are ignored (Scored)
#3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
#3.2.8 Ensure TCP SYN Cookies is enabled (Scored)
#3.2.9 Ensure IPv6 router advertisements are not accepted (Scored)

#3.3 TCP Wrappers
#3.3.1 Ensure TCP Wrappers is installed (Scored)
   # Installed by default


#3.3.2 Ensure /etc/hosts.allow is configured (Not Scored)

clear
f_banner

echo -e ""
echo -e "Setting hosts.allow and hosts.deny"
spinner
sleep 2

echo "ALL: 10.0.0.0/255.0.0.0" >> /etc/hosts.allow
echo "ALL: 192.168.0.0/255.255.0.0" >> /etc/hosts.allow
echo "ALL: 172.16.0.0/255.240.0.0" >> /etc/hosts.allow
echo "ALL: 170.55.45.42/255.255.255.255" >> /etc/hosts.allow
echo "ALL: 24.51.206.190/255.255.255.255" >> /etc/hosts.allow

#3.3.3 Ensure /etc/hosts.deny is configured (Not Scored)

#echo "ALL: ALL" >> /etc/hosts.deny

#3.3.4 Ensure permissions on /etc/hosts.allow are configured (Scored)

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

#3.3.5 Ensure permissions on /etc/hosts.deny are 644 (Scored)

#chown root:root /etc/hosts.deny
#chmod 644 /etc/hosts.deny

#3.4 Uncommon Network Protocols
#3.4.1 Ensure DCCP is disabled (Not Scored)

clear
f_banner

echo -e ""
echo -e "Disabling uncommon Network Protocols"
spinner
sleep 2

echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.2 Ensure SCTP is disabled (Not Scored)

echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.3 Ensure RDS is disabled (Not Scored)

echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.4 Ensure TIPC is disabled (Not Scored)

echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

#3.5 Firewall Configuration
#3.5.1 Ensure Firewall software is installed
#3.5.1.1 Ensure a Firewall package is installed (Scored)
#3.5.2 Configure UncomplicatedFirewall
#3.5.2.1 Ensure ufw service is enabled (Scored)
#3.5.2.2 Ensure default deny firewall policy (Scored)
#3.5.2.3 Ensure loopback traffic is configured (Scored)
#3.5.2.4 Ensure outbound connections are configured (Not Scored)
#3.5.2.5 Ensure firewall rules exist for all open ports (Not Scored)

#3.5.3 Configure nftables
#3.5.3.1 Ensure iptables are flushed (Not Scored)
#3.5.3.2 Ensure a table exists (Scored)
#3.5.3.3 Ensure base chains exist (Scored)
 
#3.5.3.4 Ensure loopback traffic is configured (Scored)
#3.5.3.5 Ensure outbound and established connections are configured (Not Scored)
#3.5.3.6 Ensure default deny firewall policy (Scored)
#3.5.3.7 Ensure nftables service is enabled (Scored)
#3.5.3.8 Ensure nftables rules are permanent (Scored)


#3.5.4 Configure iptables
#3.5.4.1.1 Ensure default deny firewall policy (Scored)
#3.5.4.1.2 Ensure loopback traffic is configured (Scored)
#3.5.4.1.3 Ensure outbound and established connections are configured (Not Scored)
#3.5.4.1.4 Ensure firewall rules exist for all open ports (Scored)
#3.5.4.2.1 Ensure IPv6 default deny firewall policy (Scored)
#3.5.4.2.2 Ensure IPv6 loopback traffic is configured (Scored)
#3.5.4.2.3 Ensure IPv6 outbound and established connections are configured (Not Scored)
#3.5.4.2.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored)

clear
f_banner

echo -e ""
echo -e "Setting up Iptables Rules"
spinner
sleep 1

sh templates/iptables-CIS.sh
cp templates/iptables-CIS.sh /etc/init.d/
chmod +x /etc/init.d/s-CIS.sh
ln -s /etc/init.d/iptables-CIS.sh /etc/rc2.d/S99iptables-CIS.sh

#3.6 Ensure wireless interfaces are disabled (Scored)

#3.7 Disable IPv6 (Not Scored)
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/g' /etc/default/grub
update-grub

#4 Logging and Auditing
#4.1 Configure System Accounting (auditd)
#4.1.1.1 Ensure auditd is installed (Scored)
clear
f_banner
echo -e ""
echo -e "Installing and configuring Auditd"

spinner
sleep 1

apt-get -y install auditd

#4.1.1.2 Ensure auditd service is enabled (Scored)
systemctl enable auditd

#4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)
sed -i 's/GRUB_CMDLINE_LINUX="ipv6.disable=1"/GRUB_CMDLINE_LINUX="ipv6.disable=1\ audit=1"/g' /etc/default/grub

#4.1.1.4 Ensure audit_backlog_limit is sufficient (Scored)

#4.1.2 Configure Data Retention
#4.1.2.1 Ensure audit log storage size is configured (Scored)
#4.1.2.2 Ensure audit logs are not automatically deleted (Scored)
#4.1.2.3 Ensure system is disabled when audit logs are full (Scored)
cp templates/auditd-CIS.conf /etc/audit/auditd.conf


#4.1.3 Ensure events that modify date and time information are collected (Scored)
#4.1.4 Ensure events that modify user/group information are collected (Scored)
#4.1.5 Ensure events that modify the system's network environment are collected (Scored)
#4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
#4.1.7 Ensure login and logout events are collected (Scored)
#4.1.8 Ensure session initiation information is collected (Scored)
#4.1.9 Ensure discretionary access control permission modification events are collected (Scored)
#4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
#4.1.11 Ensure use of privileged commands is collected (Scored)
#4.1.12 Ensure successful file system mounts are collected (Scored)
#4.1.13 Ensure file deletion events by users are collected (Scored)
#4.1.14 Ensure changes to system administration scope (sudoers) is collected (Scored)
#4.1.15 Ensure system administrator actions (sudolog) are collected (Scored)
#4.1.16 Ensure kernel module loading and unloading is collected (Scored)
#4.1.17 Ensure the audit configuration is immutable (Scored)
cp templates/audit-CIS.rules /etc/audit/audit.rules

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" } ' >> /etc/audit/audit.rules

echo " " >> /etc/audit/audit.rules
echo "#End of Audit Rules" >> /etc/audit/audit.rules
echo "-e 2" >>/etc/audit/audit.rules

cp /etc/audit/audit.rules /etc/audit/rules.d/audit.rules

#4.2 Configure Logging
#4.2.1 Configure rsyslog
#4.2.1.1 Ensure rsyslog is installed (Scored)
#4.2.1.2 Ensure rsyslog Service is enabled (Scored)
#4.2.1.3 Ensure logging is configured (Not Scored)
#4.2.1.4 Ensure rsyslog default file permissions configured (Scored)
#4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored) 
#4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts (Not Scored)

#4.2.2 Configure journald 
#4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
#4.2.2.2 Ensure journald is configured to compress large log files (Scored)
#4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)

#4.2.3 Ensure permissions on all logfiles are configured (Scored)

chmod -R g-wx,o-rwx /var/log/*

#4.3 Ensure logrotate is configured (Not Scored)


#5 Access, Authentication and Authorization
#5.1 Configure cron
#5.1.1 Ensure cron daemon is enabled (Scored)
#5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
#5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)
#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)
#5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)

chown root:root /etc/cron*
chmod og-rwx /etc/cron*

#5.1.8 Ensure at/cron is restricted to authorized users (Scored)

touch /etc/cron.allow
touch /etc/at.allow

chmod og-rwx /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow

#5.2 SSH Server Configuration
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)

#Permissions set after template copy on Line 493

#5.2.2 Ensure permissions on SSH private host key files are configured (Scored)
#5.2.3 Ensure permissions on SSH public host key files are configured (Scored) 
#5.2.4 Ensure SSH Protocol is not set to 1 (Scored)
#5.2.5 Ensure SSH LogLevel is appropriate (Scored)
#5.2.6 Ensure SSH X11 forwarding is disabled (Scored)
#5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
#5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
#5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)
#5.2.10 Ensure SSH root login is disabled (Scored)
#5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)
#5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)
#5.2.13 Ensure only strong Ciphers are used (Scored)
#5.2.14 Ensure only strong MAC algorithms are used (Scored)
#5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
#5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored)
#5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
#5.2.18 Ensure SSH access is limited (Scored)
#5.2.19 Ensure SSH warning banner is configured (Scored)
echo -n " Securing SSH..."
sed s/USERNAME/ubuntu/g templates/sshd_config-CIS > /etc/ssh/sshd_config; echo "OK"
service ssh restart

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#5.2.20 Ensure SSH PAM is enabled (Scored)
#5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
#5.2.22 Ensure SSH MaxStartups is configured (Scored)
#5.2.23 Ensure SSH MaxSessions is set to 4 or less (Scored)

#5.3 Configure PAM
#5.3.1 Ensure password creation requirements are configured (Scored)
#5.3.2 Ensure lockout for failed password attempts is configured (Scored)
#5.3.3 Ensure password reuse is limited (Scored)
#5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)

clear
f_banner

echo -e ""
echo -e "Configuring PAM"
spinner
sleep 2

cp templates/common-passwd-CIS /etc/pam.d/common-passwd
cp templates/pwquality-CIS.conf /etc/security/pwquality.conf
cp templates/common-auth-CIS /etc/pam.d/common-auth

#5.4 User Accounts and Environment
#5.4.1 Set Shadow Password Suite Parameters
#5.4.1.1 Ensure password expiration is 365 days or less (Scored)
#5.4.1.2 Ensure minimum days between password changes is is configured (Scored)
#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)

cp templates/login.defs-CIS /etc/login.defs

#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)

useradd -D -f 30

#5.4.1.5 Ensure all users last password change date is in the past (Scored)

#5.4.2 Ensure system accounts are secured (Scored)

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
    usermod -s /usr/sbin/nologin $user
  fi
  fi
done

#5.4.3 Ensure default group for the root account is GID 0 (Scored)

usermod -g 0 root

#5.4.4 Ensure default user umask is 027 or more restrictive (Scored)

sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc

#5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)

#5.5 Ensure root login is restricted to system console (Not Scored)
#5.6 Ensure access to the su command is restricted (Scored)

#6 System Maintenance
#6.1 System File Permissions
#6.1.1 Audit system file permissions (Not Scored)
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
clear
f_banner
echo -e ""
echo -e "Setting System File Permissions"
spinner
sleep 2


chown root:root /etc/passwd
chmod 644 /etc/passwd

#6.1.3 Ensure permissions on /etc/gshadow- are configured (Scored)

chown root:shadow /etc/gshadow- 
chmod g-wx,o-rwx /etc/gshadow-

#6.1.4 Ensure permissions on /etc/shadow are configured (Scored)

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

#6.1.5 Ensure permissions on /etc/group are configured (Scored)

chown root:root /etc/group
chmod 644 /etc/group

#6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)

chown root:root /etc/passwd-
chmod 600 /etc/passwd-

#6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)

chown root:root /etc/shadow-
chmod 600 /etc/shadow-

#6.1.8 Ensure permissions on /etc/group- are configured (Scored)

chown root:root /etc/group-
chmod 600 /etc/group-

#6.1.9 Ensure permissions on /etc/gshadow are configured (Scored)

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

#6.1.10 Ensure no world writable files exist (Scored)
#6.1.11 Ensure no unowned files or directories exist (Scored)
#6.1.12 Ensure no ungrouped files or directories exist (Scored)
#6.1.13 Audit SUID executables (Not Scored)
#6.1.14 Audit SGID executables (Not Scored)
#6.2 User and Group Settings
#6.2.1 Ensure password fields are not empty (Scored)
#6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
#6.2.3 Ensure all users' home directories exist (Scored)
#6.2.4 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
#6.2.5 Ensure no legacy "+" entries exist in /etc/group (Scored)
#6.2.6 Ensure root is the only UID 0 account (Scored)
#6.2.7 Ensure root PATH Integrity (Scored)
#6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)
#6.2.9 Ensure users own their home directories (Scored)
#6.2.10 Ensure users' dot files are not group or world writable (Scored)
#6.2.11 Ensure no users have
#6.2.12 Ensure no users have
#6.2.13 Ensure users'
#6.2.14 Ensure no users have
#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
#6.2.16 Ensure no duplicate UIDs exist (Scored)
#6.2.17 Ensure no duplicate GIDs exist (Scored)
#6.2.18 Ensure no duplicate user names exist (Scored)
#6.2.19 Ensure no duplicate group names exist (Scored)
#6.2.20 Ensure shadow group is empty (Scored)

clear
f_banner

cat templates/texts/bye-CIS
say_continue

reboot
