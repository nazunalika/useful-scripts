## nazunalika <tucklesepk@gmail.com>
## Please read some of the comments carefully if you plan on making any changes.

## This kickstart attempts to comply with most of the CIS Benchmarks available at
## the CIS website, http://www.cisecurity.org
## They have plenty of documents on not only CentOS, but Ubuntu, Debian, Apache, 
## etc. I highly recommend going over their documents. I also highly recommend
## viewing the CIS Benchmarks for RHEL 7 and reviewing the below kickstart
## before considering any implementation. This implementation, the benchmarks
## used may not be appropriate for your environment. Use at your own risk.

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
## CIS 1.1.3 1.1.4 1.1.7 1.1.8 1.1.9 1.1.10
logvol /  --fstype="ext4" --grow --size=2048 --name=root --vgname=centosvg
logvol /tmp --fstype="ext4" --size=4096 --name=tmp --vgname=centosvg --fsoptions=nodev,noexec,nosuid
logvol /usr --fstype="ext4" --size=4096 --name=usr --vgname=centosvg
logvol /var --fstype="ext4" --size=4096 --name=var --vgname=centosvg
logvol /var/log --fstype="ext4" --size=4096 --name=log --vgname=centosvg
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
# CIS 1.4.4 - Should only be installed on a desktop
-setroubleshoot
-mcstrans
# CIS 2.1.1 2.1.4 2.1.5 2.1.6
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
aide
# The groups in this kickstart probably already have this
rsyslog
%end

%post
## Begin Security Enhancements
### CIS 1
## CIS 1.1.6 - This might break something though it is a level 1 score.
echo "/tmp                      /var/tmp               none    bind            0 0" >> /etc/fstab

## Crontabs
# 3 am file integrity check daily - CIS 1.3.2
echo "0 3 * * * /usr/sbin/aide --check" >> /tmp/cron
# CIS 9.1.1 - changes for RPM files - Ran weekly
echo "0 5 * * 6 rpm -Va --nomtime --nosize --nomd5 --nolinkto > /root/rpmaudit" >> /tmp/cron
# CIS 7.5 - lock inactive accounts
echo "5 5 * * * useradd -D -f 35" >> /tmp/cron
crontab -u root -l | cat - /tmp/cron | crontab -u root -

cat >> /etc/sysctl.conf << EOF
## CIS 1.6.2
kernel.exec-shield = 1
## CIS 1.6.3
kernel.randomize_va_space = 2
## CIS 4.1.1 4.1.2
# Set the below to 1 if you are running a router
net.ipv4.ip_forward = 0
# Remove these if you are running a router
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# CIS 4.2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# CIS 4.2.4
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# CIS 4.2.6
net.ipv4.icmp_ignore_bogus_error_responses = 1
# CIS 4.2.8
net.ipv4.tcp_syncookies = 1

EOF

### CIS 3
## /etc/sysconfig/init - CIS 3.1
echo "# CIS 3.1" >> /etc/sysconfig/init
echo "umask 027" >> /etc/sysconfig/init

## Disbable services
# CIS 3.3 3.4
chkconfig avahi-daemon off
chkconfig cups off

## Secure ntp - CIS 3.6
sed -i 's/restrict default nomodify notrap nopeer noquery/restrict default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery/g' /etc/ntp.conf
chkconfig ntpd on

## NFS and RPC - CIS 3.8
chkconfig nfslock off
chkconfig rpcgssd off
chkconfig rpcbind off
chkconfig rpcidmapd off
chkconfig rpcsvcgssd off

## Enable postfix - CIS 3.16
systemctl enable postfix

### CIS 4
# CIS 4.5.3 - Verify Permissions on /etc/hosts.allow
[ -f /etc/hosts.allow ] && chmod 0644 /etc/hosts.allow
# CIS 4.5.5 - Verify Permissions on /etc/hosts.deny
[ -f /etc/hosts.deny ] && chmod 0644 /etc/hosts.deny

cat >/etc/modprobe.d/CIS.conf<<EOF
# CIS 4.6.1 - Disable DCCP
install dccp /bin/true
# CIS 4.6.2 - Disable SCTP
install sctp /bin/true
# CIS 4.6.3 - Disable RDS
install rds /bin/true
# CIS 4.6.4 - Disable TIPC
install tipc /bin/true
## Extra CentOS specific entries
# 1.1.18 cramfs
install cramfs /bin/true
# 1.1.19 freevxfs
install freevxfs /bin/true
# 1.1.20 jffs2
install jffs2 /bin/true
# 1.1.21 hfs
install hfs /bin/true
# 1.1.22 hfsplus
install hfsplus /bin/true
# 1.1.23 squashfs - Remove the below if you are working with squash
install squashfs /bin/true
EOF

### CIS 5
## CIS 5.1.2
chkconfig rsyslog on

## CIS 5.1.5
# Uncomment the below if you use a central logging server - This is scored
# echo "*.* @syslog.example.com" >> /etc/rsyslog.conf

## CIS 5.2.1.3
# Depending on how you feel about audit logs, you should probably rotate them.
# However, CIS does score on logs. If you are in a PCI environment, uncomment the below.
#sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf

## CIS 5.2.2 5.2.3
chkconfig auditd on
ed /etc/grub.conf << END
g/audit=1/s///g
g/kernel/s/$/ audit=1/
w
q
END

## CIS 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9
## CIS 5.2.10, 5.2.11, 5.2.12, 5.2.13, 5.2.14, 5.2.16
## CIS 5.2.17, 5.2.18
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
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
## Monitor's unsuccessful attempts to access files
# Highly recommended you keep this. It will cover your ass.
# It will also allow you to tell people who are developers to knock their shit off
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
## Monitors mounting events for users
# You can probably take these out
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
## Collect file deletion events by a user
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
## Collect changes to System Administration Scope
# Note: This only records /etc/sudoers and doesn't watch /etc/sudoers.d
-w /etc/sudoers -p wa -k scope
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

### CIS 6
## CIS 6.1.2
chkconfig crond on

## CIS 6.1.4 - Set User/Group Owner and Permission on /etc/crontab
## CIS 6.1.5 - Set User/Group Owner and Permission on /etc/cron.hourly
## CIS 6.1.6 - Set User/Group Owner and Permission on /etc/cron.daily
## CIS 6.1.7 - Set User/Group Owner and Permission on /etc/cron.weekly
## CIS 6.1.8 - Set User/Group Owner and Permission on /etc/cron.monthly
## CIS 6.1.9 - Set User/Group Owner and Permission on /etc/cron.d
chown root:root /etc/cron{tab,.{hourly,daily,weekly,monthly,.d}}
chmod og-rwx /etc/cron{tab,.{hourly,daily,weekly,monthly,.d}}

## CIS 6.1.10
# This may not be required, but something to think about. This prevents people from running at.
rm /etc/at.deny
[ ! -f /etc/at.allow ] && touch /etc/at.allow && echo "root" >> /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow

## CIS 6.1.11
# This is up to you. This prevents users (except root) from running cron.
rm /etc/cron.deny
[ ! -f /etc/cron.allow ] && touch /etc/cron.allow && echo "root" >> /etc/cron.allow
chmod og-rwx /etc/cron.allow
chown root:root /etc/cron.allow

## CIS 6.2.4 6.2.5 6.2.10 6.2.11 6.2.12
# Some of these may or may not be needed. Tread lightly. Uncomment them if you want them.
# ** NOTE: The wonderful company known as Oracle likes to use installers that require X.
# **       You'll either need to make an exception to keep these unchanged or enable them
# **       again at a "as needed" basis.
#sed -i '/X11Forwarding /s/.*/X11Forwarding no/' /etc/ssh/sshd_config
# CIS 6.2.5 - Set SSH MaxAuthTries to 4 or Less
#sed -i '/MaxAuthTries/s/.*/MaxAuthTries 4/' /etc/ssh/sshd_config
# CIS 6.2.10 - Do Not Allow Users to Set Environment Options
#sed -i '/PermitUserEnvironment/s/.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
# CIS 6.2.11 - Use Only Approved Cipher in Counter Mode
#sed -i '/# Ciphers and keying/a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
# CIS 6.2.12 - Set Idle Timeout Interval for User Login
#sed -i '/ClientAliveInterval/s/.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
#sed -i '/ClientAliveCountMax/s/.*/ClientAlivecountMax 0/' /etc/ssh/sshd_config

## CIS 6.2.8
# Your company may need an override for this. Otherwise, uncomment/comment the appropriate lines.
# You may want to read all of 6.2. Some of them are default, but others are not.
# Some to look at: 6.2.5, 6.2.7, 6.2.9, 6.2.10, 6.2.11, 6.2.12
sed -i 's/^#PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
#sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

## CIS 6.2.13
# This one is a little tricky. If you use systems without LDAP/AD, consider creating restrictions.
# A commented example is below. Because I use AD, this isn't completely required.
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

## The next few are part of 6.3
## Consider looking at 6.3.2, 6.3.3, 6.3.4 if you do NOT use LDAP or Active Directory
## CIS 6.3.1
## Already done earlier in the kickstart
authconfig --passalgo=sha512 --update

## CIS 6.3.3 - Set Lockout for Failed Password Attempts
## CIS 6.3.4 - Limit Password Reuse
# Null, because we use AD, there is not a reason to use these PAM configurations
# All system account passwords are never created or provided.
## CIS 6.3.2 - Set Password Creation Requirement Parameters Using pam_pwquality
cat >> /etc/security/pwquality.conf << EOF
minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOF

## CIS 6.5
# This is for anyone in the wheel group. If you don't want to restrict access to su, comment the below.
# Read /etc/pam.d/su for more information
sed '/pam_wheel.so use_uid/ s/#auth/auth/g' /etc/pam.d/su

### CIS 7
## CIS 7.1.1, 7.1.2
# In a PCI environment, this is ABSOLUTELY needed, even if you are using LDAP/Active Directory
sed -i '/PASS_MAX_DAYS/ s/99999/84/' /etc/login.defs
sed -i '/PASS_MIN_DAYS/ s/0/7/' /etc/login.defs

## CIS 7.5
# This sets a default option that if a user is inactive for more than X days, they will be disabled.
# This is 35 days. Change as appropriate. The "cron" will perform this also.
# Note: This does not affect LDAP or AD users
useradd -D -f 35

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

