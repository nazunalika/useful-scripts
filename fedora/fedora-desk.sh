#!/bin/bash
# tucklesepk@gmail.com

# Varibles
## Package lists
STANDARD="firefox thunderbird pidgin clementine vlc"

## Place a comment behind any of the next lines to remove it from the selection of packages
## Music/video codecs
CODECS="gstreamer-* gstreamer1-* ffmpeg libmpg123 lame-libs"
#CODECS="gstreamer{1,}-{plugin-crystalhd,ffmpeg,rtsp,libav,plugins-{good,ugly,bad{,-free,-nonfree,-freeworld,-extras{-extras}}} ffmpeg libmpg123 lame-libs"
## Note: The below is just for reference of fedora 17 to 18.
#CODECS="gstreamer-{ffmpeg,rtsp,plugins-{good,ugly,bad{,-free,-nonfree}}} gstreamer1-{ffmpeg,libav,plugins-{good,ugly,bad{,-free,-nonfree}}} ffmpeg"

## Set the variables here for optional software
OPTIONAL[1]="skype"
OPTIONAL[2]="teamviewer"
OPTIONAL[3]="wine"
OPTIONAL[4]="steam"
OPTIONAL[5]="audacity-freeworld"

## Extras. You may add anything inside of this variable to add to the list of packages.
## It's empty by default.
EXTRAS=""

## Drivers
## In here, if you have drivers you'd like to install, place them in here
## assuming yum is aware of the package in the repos. A common one is kmod-nvidia.
## However, if you plan on installing kmod-nvidia, it is HIGHLY recommended
## to do a yum update first, reboot, and then install kmod-nvidia.
DRIVERS=""

## As for this, if you are installing kmod-nvidia, uncomment this.
## Highly recommended if you plan on playing 32 bit games in wine or steam.
#32LIBS="xorg-x11-drv-nvidia-libs.i686"

# Functions
p1_checkroot() {
if [[ $UID != 0 ]]; then
	echo "Not root."
	exit
fi
}
p2_checkwget() {
if [ -z $(rpm -qa | grep wget) ]; then dnf install wget -y ; fi
}

a1_repos() {
dnf install --nogpgcheck http://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm http://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm -y
wget -q -O /etc/pki/rpm-gpg/SYRKIT-GPG-KEY http://syrkit.bromosapien.net:8081/SYRKIT-GPG-KEY.pub
wget http://syrkit.bromosapien.net:8081/syndra/syndra-release-22-1.noarch.rpm
dnf install syndra-release-22-1.noarch.rpm -y
}

a2_install() {
dnf install $CODECS $STANDARD ${OPTIONAL[*]} $EXTRAS $32LIBS --exclude=*docs --exclude=*debug --exclude=*devel -y
}
a3_update() {
dnf update -y
}
f1_skype_pa_fix() {
sed -i 's/Exec=/Exec=env PULSE_LATENCY_MSEC=30 /' /usr/share/applications/skype.desktop
}

p1_checkroot
p2_checkwget
a1_repos
a2_install
a3_update
if [ -n ${OPTIONAL[1]} ]; then
	f1_skype_pa_fix
fi
echo "Done."
