## nazunalika <tucklesepk@gmail.com>
## Please read some of the comments carefully if you plan on making any changes.

## This kickstart attempts to comply with most of the CIS Benchmarks available at
## the CIS website, http://www.cisecurity.org
## They have plenty of documents on not only CentOS, but Ubuntu, Debian, Apache, 
## etc. I highly recommend going over their documents. I also highly recommend
## viewing the CIS Benchmarks for RHEL 7 and reviewing the below kickstart
## before considering any implementation. This implementation, the benchmarks
## used may not be appropriate for your environment. Use at your own risk.

## As a note, any benchmarks that are in the PDF that are not listed here are
## for the following reasons:
##   -> What's listed on the benchmarks is not installed/configured by default
##   -> They are the default settings
##   -> They are wanting a package/service that has a Red Hat defined default
##      Example: firewalld is used to manage iptables
##   -> They are not applicable at a moment's notice in the kickstart and must
##      be configured later after a system's deployment
##   -> A configuration can potentially halt a production server and can cause
##      unnecessary work to bring it back online

#version=RHEL6
install
url --url=http://mirror.centos.org/centos/6/os/x86_64/
lang en_US.UTF-8
keyboard us
## Your network device may be different. Use with caution.
network --onboot yes --device eth0 --mtu=1500 --bootproto dhcp
rootpw  --iscrypted $6$HASH
# Reboot after installation
reboot
firewall --service=ssh
authconfig --enableshadow --passalgo=sha512
selinux --enforcing
timezone --utc America/Phoenix
bootloader --location=mbr --driveorder=sda --append="crashkernel=auto rhgb rhgb quiet"

clearpart --all --initlabel --drives=sda
zerombr
part pv.14 --fstype="lvmpv" --ondisk=sda --size=1 --grow
part /boot --fstype="ext4" --ondisk=sda --size=500
volgroup centosvg --pesize=4096 pv.14
logvol swap  --fstype="swap" --size=4096 --name=swap --vgname=centosvg
## CIS 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.1.7 1.1.8 1.1.9 1.1.10
##     1.1.11 1.1.12 1.1.13 1.1.14
logvol /  --fstype="ext4" --grow --size=2048 --name=root --vgname=centosvg
logvol /tmp --fstype="ext4" --size=4096 --name=tmp --vgname=centosvg --fsoptions=nodev,noexec,nosuid
logvol /usr --fstype="ext4" --size=4096 --name=usr --vgname=centosvg
logvol /var --fstype="ext4" --size=4096 --name=var --vgname=centosvg
logvol /var/log --fstype="ext4" --size=4096 --name=log --vgname=centosvg
logvol /var/tmp --fstype="ext4" --size=4096 --name=vartmp --vgname=centosvg --fsoptions=nodev,noexec,nosuid
logvol /var/log/audit --fstype="ext4" --size=4096 --name=audit --vgname=centosvg
logvol /home --fstype="ext4" --size=4096 --name=home --vgname=centosvg --fsoptions=nodev

# Additional repo
repo --name=base --baseurl=http://mirror.centos.org/centos/6/os/x86_64/
repo --name=updates --baseurl=http://mirror.centos.org/centos/6/updates/x86_64/
repo --name=epel --baseurl=http://download.fedoraproject.org/pub/epel/6/x86_64/

%packages
@base
@core
pax
oddjob
sgpio
certmonger
pam_krb5
krb5-workstation
perl-DBD-SQLite
zsh
jwhois
vim-enhanced
# CIS 1.6.1.4 1.6.1.5
-setroubleshoot
-mcstrans
# CIS 2.3.1 2.3.2 2.3.3 2.3.4
-telnet-server
-rsh-server
-ypbind
-ypserv
# Stuff we find useful
yum
centos-release
epel-release
dos2unix
unix2dos
tmux
bash
policycoreutils
policycoreutils-python
ntp
ntpdate
sysstat
tcpdump
# CIS 3.4.1
postfix
tcp_wrappers
iptables
iptables-ipv6
# Needed for remote auth
sssd-ad
sssd-krb5-common
sssd-krb5
sssd-dbus
sssd-common
sssd
sssd-client
sssd-ldap
adcli
samba-common
openldap-clients
# Needed for kerberos
krb5-libs
krb5-workstation
pam_krb5
samba-winbind-krb5-locator
# Needed for configuration management
#salt
#salt-minion
# We're installing aide as an auditing tool
# If you use prelinking, set it to 0 in /etc/sysconfig/prelink
# Prelink is NOT installed. CIS 1.5.4
# CIS 1.3.1
aide
# The groups in this kickstart probably already have this
rsyslog
%end

%post
## Begin Security Enhancements
## CIS 1.1.15 - Ensure nodev option for /dev/shm
## CIS 1.1.16 - Ensure nosuid option for /dev/shm
## CIS 1.1.17 - Ensure noexec option for /dev/shm
echo "tmpfs               /dev/shm        tmpfs   defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab

# CIS 1.4.4
sed -i 's/PROMPT=yes/PROMPT=no/g' /etc/sysconfig/init

## Crontabs
# 3 am file integrity check daily - CIS 1.3.2
echo "0 3 * * * /usr/sbin/aide --check" >> /tmp/cron
# CIS 9.1.1 - changes for RPM files - Ran weekly
echo "0 5 * * 6 rpm -Va --nomtime --nosize --nomd5 --nolinkto > /root/rpmaudit" >> /tmp/cron
# CIS 7.5 - lock inactive accounts
echo "5 5 * * * useradd -D -f 30" >> /tmp/cron
crontab -u root -l | cat - /tmp/cron | crontab -u root -

cat >> /etc/sysctl.conf << EOF
## CIS 1.5.1
# Uncomment if you want core dumps restricted
#fs.suid_dumpable = 0
## CIS 1.5.3
kernel.randomize_va_space = 2
## CIS 3.1.1 3.1.2 3.2.2 3.2.3 3.2.7
# Set the below to 1 if you are running a router
net.ipv4.ip_forward = 0
# Remove these if you are running a router
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Remove these especially if ospf or bgp are used
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# CIS 3.2.1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# CIS 3.2.4
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# CIS 3.2.5
net.ipv4.icmp_echo_ignore_broadcasts = 1
# CIS 3.2.6
net.ipv4.icmp_ignore_bogus_error_responses = 1
# CIS 3.2.8
net.ipv4.tcp_syncookies = 1

EOF

## CIS 1.5.1
# Uncomment if you want core dumps restricted
# echo "* hard core 0" >> /etc/security/limits.d/corezero.conf

## /etc/sysconfig/init - CIS 3.1
echo "# CIS 3.1" >> /etc/sysconfig/init
echo "umask 027" >> /etc/sysconfig/init

## Disbable services
# CIS 2.2.3 2.2.4
chkconfig avahi-daemon off
chkconfig cups off

## Secure ntp - CIS 2.2.1.1
sed -i 's/restrict default nomodify notrap nopeer noquery/restrict default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery/g' /etc/ntp.conf
chkconfig ntpd on

## NFS and RPC - CIS 2.2.7
# Lising others just in case
chkconfig nfs off
chkconfig rpcbind off
chkconfig rpcgssd off
chkconfig rpcidmapd off
chkconfig rpcsvcgssd off

## Enable postfix - CIS 2.2.1.5
systemctl enable postfix

### CIS 4
# CIS 4.5.3 - Verify Permissions on /etc/hosts.allow
[ -f /etc/hosts.allow ] && chmod 0644 /etc/hosts.allow
# CIS 4.5.5 - Verify Permissions on /etc/hosts.deny
[ -f /etc/hosts.deny ] && chmod 0644 /etc/hosts.deny

cat >/etc/modprobe.d/CIS.conf<<EOF
# CIS 3.5.1 - Disable DCCP
install dccp /bin/true
# CIS 3.5.2 - Disable SCTP
install sctp /bin/true
# CIS 3.5.3 - Disable RDS
install rds /bin/true
# CIS 3.5.4 - Disable TIPC
install tipc /bin/true
## Extra CentOS specific entries
# 1.1.1 cramfs
install cramfs /bin/true
# 1.1.2 freevxfs
install freevxfs /bin/true
# 1.1.3 jffs2
install jffs2 /bin/true
# 1.1.4 hfs
install hfs /bin/true
# 1.1.5 hfsplus
install hfsplus /bin/true
# 1.1.6 squashfs - Remove the below if you are working with squash
install squashfs /bin/true
# 1.1.7 udf - Remove the below if you are working with squash
install udf /bin/true
EOF

### CIS 5
## CIS 5.1.2
chkconfig rsyslog on

## CIS 5.1.5
# Uncomment the below if you use a central logging server - This is scored
# echo "*.* @syslog.example.com" >> /etc/rsyslog.conf

## CIS 4.1.1.3
# Depending on how you feel about audit logs, you should probably rotate them.
# However, CIS does score on logs. If you are in a PCI environment, uncomment the below.
#sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf

## CIS 4.1.2 4.1.3
chkconfig auditd on
ed /etc/grub.conf << END
g/audit=1/s///g
g/kernel/s/$/ audit=1/
w
q
END

## CIS 4.1.4 4.1.5 4.1.6 4.1.7 4.1.8 4.1.9 4.1.10 4.1.11
##     4.1.12 4.1.13 4.1.14 4.1.15 4.1.16 4.1.17 4.1.18
# Honestly, depending on how you feel, these may not be necessary.
# But if you are in a PCI environment, you may want to consider this.
# These are mostly level 2 scores.
cat > /etc/audit/rules.d/cis.rules << EOF
## Records when system date and time has been modified
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
## Records when events occur that modify user and group passwords and ID's
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
## Records changes to network environment files or system calls
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
## Monitors SELinux Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
## Monitors login/logout/failed login events
# To be fair, these are normally logged in /var/log/secure
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
## Monitor session initiation events
## This will track file changes within sessions
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
## Monitor changes for files for UID's above 1000
# You can take this out if you are on a non-PCI system
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
## Monitor's unsuccessful attempts to access files
# Highly recommended you keep this. It will cover your ass.
# It will also allow you to tell people who are developers to knock their shit off
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
## Monitors mounting events for users
# You can probably take these out
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
## Collect file deletion events by a user
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
## Collect changes to System Administration Scope
# Note: This only records /etc/sudoers and doesn't watch /etc/sudoers.d
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
## Collect System Administrator Actions (sudolog)
# Uncomment this if you really need it. This is somewhat satisfied by /var/log/secure
#-w /var/log/sudo.log -p wa -k actions
## Collect Kernel Module Loading and Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
## Prevents auditctl from working
-e 2
EOF

## Monitor privileged programs (setuid/setgid) to determine if unprivileged users are running them
# This list is generated using this command:
# find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }'
cat > /etc/audit/rules.d/monitor.rules << EOF
# find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }'
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ksu -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
EOF

/sbin/augenrules

## CIS 5.1.1
chkconfig crond on

## CIS 5.1.2 - Set User/Group Owner and Permission on /etc/crontab
## CIS 5.1.3 - Set User/Group Owner and Permission on /etc/cron.hourly
## CIS 5.1.4 - Set User/Group Owner and Permission on /etc/cron.daily
## CIS 5.1.5 - Set User/Group Owner and Permission on /etc/cron.weekly
## CIS 5.1.6 - Set User/Group Owner and Permission on /etc/cron.monthly
## CIS 5.1.7 - Set User/Group Owner and Permission on /etc/cron.d
chown root:root /etc/cron{tab,.{hourly,daily,weekly,monthly,.d}}
chmod og-rwx /etc/cron{tab,.{hourly,daily,weekly,monthly,.d}}

## CIS 5.1.8
# This may not be required, but something to think about. This prevents people from running at.
rm /etc/at.deny
[ ! -f /etc/at.allow ] && touch /etc/at.allow && echo "root" >> /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

# This is up to you. This prevents users (except root) from running cron.
rm /etc/cron.deny
[ ! -f /etc/cron.allow ] && touch /etc/cron.allow && echo "root" >> /etc/cron.allow
chmod og-rwx /etc/cron.allow
chown root:root /etc/cron.allow

# Some of these may or may not be needed. Tread lightly. Uncomment them if you want them.
# And yes, they are scored.
# ** NOTE: The wonderful company known as Oracle likes to use installers that require X.
# **       You'll either need to make an exception to keep these unchanged or enable them
# **       again at a "as needed" basis.
## CIS 5.2.4 - Disable X11Forwarding
# sed -i '/X11Forwarding /s/.*/X11Forwarding no/' /etc/ssh/sshd_config
## CIS 5.2.5 - Set SSH MaxAuthTries to 4 or Less
# sed -i '/MaxAuthTries/s/.*/MaxAuthTries 4/' /etc/ssh/sshd_config
## CIS 5.2.10 - Do Not Allow Users to Set Environment Options
# sed -i '/PermitUserEnvironment/s/.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
## CIS 5.2.11 - Use Only Approved Cipher in Counter Mode
# sed -i '/# Ciphers and keying/a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
## CIS 5.2.12 - Set Idle Timeout Interval for User Login
# sed -i '/ClientAliveInterval/s/.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
# sed -i '/ClientAliveCountMax/s/.*/ClientAlivecountMax 0/' /etc/ssh/sshd_config

## CIS 5.2.8
# Your company may need an override for this. Regardless, uncomment/comment the appropriate lines.
# sed -i 's/^#PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

## CIS 5.2.15
# This one is a little tricky. If you use systems without LDAP/AD, consider creating restrictions.
# A commented example is below. Because I use AD, this isn't completely required as I can restrict
# from sssd, realm, or (very limited) group policies.
#echo "AllowGroups root ssh-users" >> /etc/ssh/sshd_config
#echo "DenyGroups blacklist anonymous" >> /etc/ssh/sshd_config
#/usr/sbin/groupadd -g 501 l_sysadmins
#/usr/sbin/groupadd -g 502 ssh-users
#/usr/sbin/groupadd -g 503 blacklist
#/usr/sbin/groupadd -g 504 anonymous


## CIS 6.2.14
# You need a banner. Consider changing this to your environment.
sed -i '/# Banner none/a Banner /etc/banner' /etc/ssh/sshd_config
cat > /etc/banner << EOF
                      ___           ___           ___
                     /\  \         /\  \         /\__\
                    /::\  \       /::\  \       /::|  |
                   /:/\ \  \     /:/\ \  \     /:|:|  |
                  _\:\~\ \  \   _\:\~\ \  \   /:/|:|  |__
                 /\ \:\ \ \__\ /\ \:\ \ \__\ /:/ |:| /\__\
                 \:\ \:\ \/__/ \:\ \:\ \/__/ \/__|:|/:/  /
                  \:\ \:\__\    \:\ \:\__\       |:/:/  /
                   \:\/:/  /     \:\/:/  /       |::/  /
                    \::/  /       \::/  /        /:/  /
                     \/__/         \/__/         \/__/

         If you are not an authorized user, please disconnect now.
                        Your IP is being logged

  Any activity done on this machine is logged and monitored at all times. Any
  unauthorized access by individuals without explicit permission are subject
  to having their activities recorded, monitored, and/or examined by any
  authorized person, including law enforcement. In the course of any system
  maintenance, authorized users are also monitored. Any and all material
  may be disclosed as appropriate.

EOF

## CIS 6.3.1
## Already done earlier in the kickstart
authconfig --passalgo=sha512 --update

## CIS 5.3.2 - Set Lockout for Failed Password Attempts
# Unsure how to properly get this in. It's managed via config management
## CIS 5.3.3 - Limit Password Reuse
sed -i '/^password\s*sufficient\s*pam_unix.so/ s/$/ remember=5/' /etc/pam.d/password-auth
sed -i '/^password\s*sufficient\s*pam_unix.so/ s/$/ remember=5/' /etc/pam.d/system-auth
# Note: It's never recommended to provide passwords for system/service accounts.
## CIS 5.3.1 - Set Password Creation Requirement Parameters Using pam_pwquality
cat >> /etc/security/pwquality.conf << EOF
minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOF

## CIS 5.6
# This is for anyone in the wheel group. If you don't want to restrict access to su, comment the below.
# Read /etc/pam.d/su for more information
sed '/pam_wheel.so use_uid/ s/#auth/auth/g' /etc/pam.d/su

## CIS 5.4.1.1 5.4.1.2
# In a PCI environment, this is ABSOLUTELY needed, even if you are using LDAP/Active Directory
sed -i '/PASS_MAX_DAYS/ s/99999/84/' /etc/login.defs
sed -i '/PASS_MIN_DAYS/ s/0/7/' /etc/login.defs

## CIS 5.4.1.4
# This sets a default option that if a user is inactive for more than X days, they will be disabled.
# This is 35 days. Change as appropriate. The "cron" will perform this also.
# Note: This does not affect LDAP or AD users
useradd -D -f 30

## CIS 8.1, 8.2
# This removes OS information. Uncomment if you really want to. PCI environments WILL require this.
cat /dev/null > /etc/issue
cat /dev/null > /etc/issue.net
# Consider settings an /etc/motd as part of 8.2

## If you have clients that connect to Katello or spacewalk, configure it here

## Running salt? Need an update? Sync up our configs and reboot
yum update -y
#sed -i '16i master: bro-ns-01.bromosapien.net' /etc/salt/minion
#systemctl enable salt-minion
#systemctl start salt-minion
#salt-call state.highstate
init 6
%end

