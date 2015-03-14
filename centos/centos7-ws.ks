#version=RHEL7
# System authorization information
auth --enableshadow --passalgo=sha512

# Use network installation
# If you are using a dvd or some other source, change/comment the url and/or uncomment cdrom.
url --url="http://10.100.0.1/os/c7/x86_64"
# cdrom
# Run the Setup Agent on first boot
firstboot --enable
ignoredisk --only-use=sda
# Keyboard layouts
keyboard --vckeymap=us --xlayouts='us'
# System language
lang en_US.UTF-8

# Network information
network  --bootproto=dhcp --ipv6=auto --activate
#network  --bootproto=dhcp --device=ens192 --ipv6=auto --activate
#network  --hostname=zera3.angelsofclockwork.net
# Root password
#rootpw --iscrypted 
# System timezone
timezone America/Phoenix --isUtc --nontp
#user --groups=wheel --name=nazu --password= --iscrypted --gecos="Default User"
# X Window System configuration information
xconfig  --startxonboot
# System bootloader configuration
bootloader --location=mbr --boot-drive=sda
autopart --type=lvm
# Partition clearing information
clearpart --all --initlabel --drives=sda
# Agree with the EULA.
eula --agreed
# Add some repos in there, because we need it.
# If you don't have your own local repo, comment the top IP URL's and uncomment the "mirrors"
repo --name=centos --baseurl="http://10.100.0.1/os/c7/x86_64"
repo --name=centos-updates --baseurl="http://10.100.0.1/CentOS/$releasever/updates/$basearch"
#repo --name=centos --baseurl="http://mirror.centos.org/centos/$releasever/os/$basearch"
#repo --name=centos-updates --baseurl="http://mirror.centos.org/centos/$releasever/updates/$basearch"
repo --name=syndra --baseurl="http://syrkit.bromosapien.net:8081/syndra/"
repo --name=epel --mirrorlist="https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=x86_64"
repo --name=nux --baseurl="http://li.nux.ro/download/nux/dextop/el7/$basearch" --excludepkgs=skype,msttcore-fonts-installer
repo --name=syndra-testing --baseurl="http://syrkit.bromosapien.net:8081/syrkit-temp"

# Make sure that we reboot at the end. 
reboot

%packages
@base
@compat-libraries
@core
@desktop-debugging
@dial-up
@directory-client
@fonts
@input-methods
@internet-applications
@internet-browser
@kde-apps
@kde-desktop
@kde-media
@multimedia
@network-file-system-client
@print-client
@x11
totem
vim-enhanced
# Keep packages out that I don't need
-rhino
-jline
-icedtea-web
# Packages that are out of the base
clementine
vlc
skype
#msttcore-fonts-installer
pidgin
finch
thunderbird
google-chrome-stable
## Codecs
ffmpeg
gstreamer-ffmpeg
gstreamer-plugins-base
gstreamer-plugins-base-tools
gstreamer-plugins-bad
gstreamer-plugins-bad-free
gstreamer-plugins-bad-nonfree
gstreamer-plugins-good
gstreamer-plugins-ugly
gstreamer1-plugins-base
gstreamer1-plugins-base-tools
gstreamer1-plugins-bad-free
gstreamer1-plugins-bad-freeworld
gstreamer1-plugins-good
gstreamer1-plugins-ugly
gstreamer1-vaapi
gstreamer1-libav

## releases
nux-dextop-release
epel-release
syndra-el-release

%end
%post
# Make some changes
sed -i '/protect=0/a exclude=skype' /etc/yum.repos.d/nux-dextop.repo
sed -i 's/Exec=/Exec=env PULSE_LATENCY_MSEC=30 /' /usr/share/applications/skype.desktop
# Import the GPG keys. We don't want to get fucked over later.
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-nux.ro
# Making sure we're fully up to date
yum update -y
# Set to runlevel 5 :)
systemctl set-default graphical.target
# Rebooting just in case, because sometimes "reboot" is not honored at the top
reboot
%end
