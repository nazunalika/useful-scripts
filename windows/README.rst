Windows Scripts
^^^^^^^^^^^^^^^

These are some of my windows scripts. I'm not a Windows admin. However, a lot of people I know use windows exclusively for reasons such as not being in IT and being gamers. And also, some are casual users. These scripts are the ones I use to make my life easier when reinstalling Windows or performing fresh installs of Windows for others.

Windows 10 Cleanup
------------------

One of the scripts you'll notice is called win10clean.ps1. It is a powershell script that aims at debloating Windows 10 as much as possible. Right now, I have it as close as I possibly can for the latest update (1703). I'm still tweaking it a little bit. So far, it seems to work ok after a setup or even during the Setupcomplete.cmd calls.

Here are the things you probably want to know about this script and what it does:

 * Removes almost all of the Windows 10 default apps
 * Removes the Windows 10 Store (this cannot be undone without a reset)
 * Disables unneeded services
 * Disables xbox shenanigans
 * Enables true mouse/removes mouse accleration
 * Disables driver updates
 * Disables sticky keys/ease of access
 * Disables Windows Update Seeding
 * Disables Cortana
 * Disables Windows Defender
 * Disables and removes OneDrive integration
 * Attempts to disable the suggestions and content delivery
 * Supports the addition of a custom layout for new users (for sysprep/setupcomplete folks)
 * Modifies \etc\hosts to block out telemetry hosts
 * Blocks telemetry in the windows firewall

There is a variable to control almost all of the changes this script can make. Please make sure to read the comments and review the script. *Do not ever run scripts blindly. Do your homework and review the script.* Additionally, **this script is meant for more tech-savvy individuals. If you do not understand powershell or have basic understanding of the registry and the various components of Windows, you may cause yourself a lot of grief or issues, but usually the former.**

If you plan on running this script, please keep in mind your system will reboot. There is a variable to control this if you do not wish to reboot.

As a note, this only works on the Pro, Enterprise, and Education SKU's. I will not support the home edition.
