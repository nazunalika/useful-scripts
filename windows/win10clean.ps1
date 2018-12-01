# PowerShell script to basically debloat Windows 10 as much as possible.
# Louis Abel

#############################################################################################
# History
#
# 05/16/2017 - Initial creation
# 05/17/2017 - Added functions for messages
# 05/20/2017 - Fixed defender icon tray
#            - Fixed the onedrive stuff to be consistent
# 10/17/2017 - Fall Update
# 04/30/2018 - Tested with April update - no changes
# 08/11/2018 - Added more apps
# 11/18/2018 - Added notes about new installs

#############################################################################################
# I am not a powershell scripter and I do not claim to be. A lot of the stuff I did here was
# done based on my basic knowledge of bash and perl and remembering powershell from my school
# courses. I could give these scripts commandline arguments and other fancy stuff, but I'm
# not willing to. Instead, there are variables that can be modified that will alter the
# script's runtime. Please make sure to read all comments.
# 
# Your system will reboot when the script is done running.


#############################################################################################
# Disclaimer: The user takes full responsibility running this script. This script comes with
#             no warranties. Any damages or issues that occur with running this script is
#             of the full responsibility of the owner of the system of which it was ran.
#             In other words, I do not and will not support you.
#

#############################################################################################
# FAQ:
#  1. How do I undo this?
#    a. I don't have an undo script. You can look over this script and determine what I did.
#       If you want to reinstall all the store apps, you can go to the store app (if you kept
#       it) and install it all from there by hand. Honestly, if you want the bloat back, you
#       are recommended to clean install and not running this script.
#
#  2. Why are you removing the store? Can't you just disable it in the registry?
#    a. Yes, I could just disable it in the registry. But I'd rather remove it. If you want
#       to just disable it: "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
#
#  3. Can I run this on a laptop that already has Windows 10 installed?
#    a. Sure you can. You'll probably find some of the apps do NOT get removed. I personally
#       feel this should be run on a clean install or a system reset. I believe a reset will
#       remove all the apps. 
#
#  4. What Windows 10 versions does this work on?
#    a. Pro (most changes), Enterprise, Education SKU's are supported.
#

# This script has been created by Shoot the J Ltd. Remember, we always connect on 3's.
# Shoot the J Ltd: This isn't a transition, it's a statement.™

# Variables
$RemoveApps = 1
$RemoveOneDrive = 1
$RemoveStore = 1
$DisableServices = 1
$DisableDefender = 1
$EnableTrueMouse = 1
$DisableTelemetry = 1
$DisableTelemetryEtcHosts = 1
$EnableSkype = 1
$UsabilityFeatures = 1
$PrivacyTweaks = 1
# If you are using this during the final stages of an install ($OEM$ folders) this
# should be set to 0 and the drivers you don't want updated should be manually selected
# in device manager.
$DisableDriverUpdates = 0
# There is a problem where rebooting during the final stages poses problems for builds of 1809
# and higher. This is disabled in my builds as a result. If you are running this after a full install
# and you are on the deskop, then setting this to a 1 is fine.
$RestartComputer = 0
$ImportLayout = 1

# All of our apps
$applist = @(
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingMaps"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingTravel"
    "Microsoft.BingWeather"
    "Microsoft.BioEnrollment"
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.FreshPaint"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftJackpot"
    "Microsoft.MicrosoftJigsaw"
    "Microsoft.MicrosoftMahjong"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftSudoku"
    "Microsoft.MinecraftUWP"
    "Microsoft.MovieMoments"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.SkypeApp"
    "Microsoft.SkypeWiFi"
    "Microsoft.StorePurchaseApp"
    "Microsoft.Studios.Wordament"
    "Microsoft.Wallet"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCamera"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsReadingList"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.Zune"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsReadingList"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxGameOverlay"
    "*xboxapp*"
    "*minecraft*"
    "*MicrosoftOfficeHub*"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.ContactSupport"
    "Microsoft.CBSPreview"
)

# Some are part of 2017 update and some other random OEM things
$extraAppList = @(
    "*MarchOfEmpires*"
    "9E2F88E3.Twitter"
    "4DF9E0F8.Netflix"
    "2FE3CB00.PicsArt-PhotoStudio"
    "D52A8D61.FarmVille2CountryEscape"
    "6Wunderkinder.Wunderlist"
    "ClearChannelRadioDigital.iHeartRadio"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "king.com*"
    "PandoraMediaInc.29680B314EFC2"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "TuneIn.TuneInRadio"
    "*DragonManiaLegends"
    "*HiddenCityMysteryofShadows"
    "*MarchofEmpires"
    "06DAC6F6.StumbleUpon"
    "09B6C2D8.TheTreasuresofMontezuma3"
    "134D4F5B.Box*"
    "1430GreenfieldTechnologie.PuzzleTouch*"
    "26720RandomSaladGamesLLC.HeartsDeluxe*"
    "26720RandomSaladGamesLLC.SimpleSolitaire*"
    "29982CsabaHarmath.UnCompress*"
    "2FE3CB00.PicsArt-PhotoStudio*"
    "32988BernardoZamora.SolitaireHD"
    "37442SublimeCo.AlarmClockForYou"
    "46928bounde.EclipseManager*"
    "4AE8B7C2.Booking.comPartnerEdition*"
    "5269FriedChicken.YouTubeVideosDownloader*"
    "5A894077.McAfeeSecurity"
    "64885BlueEdge.OneCalendar*"
    "6Wunderkinder.Wunderlist"
    "7906AAC0.TOSHIBACanadaPartners*"
    "7906AAC0.ToshibaCanadaWarrantyService*"
    "7EE7776C.LinkedInforWindows"
    "7digitalLtd.7digitalMusicStore*"
    "828B5831.HiddenCityMysteryofShadows"
    "89006A2E.AutodeskSketchBook*"
    "95FE1D22.VUDUMoviesandTV"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.DragonManiaLegends*"
    "A278AB0D.MarchofEmpires"
    "A34E4AAB.YogaChef*"
    "AD2F1837.DiscoverHPTouchpointManager"
    "AD2F1837.HPJumpStart"
    "AD2F1837.HPPowerManager"
    "AD2F1837.HPWelcome"
    "AD2F1837.SmartfriendbyHPCare"
    "ASUSCloudCorporation.MobileFileExplorer*"
    "AccuWeather.AccuWeatherforWindows8*"
    "AcerIncorporated*"
    "AcerIncorporated.AcerExplorer"
    "ActiproSoftwareLLC*"
    "ActiproSoftwareLLC.562882FEEB491"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "AdobeSystemsIncorporated.AdobeRevel*"
    "Amazon.com.Amazon*"
    "AppUp.IntelAppUpCatalogueAppWorldwideEdition*"
    "B9ECED6F.ASUSGIFTBOX*"
    "B9ECED6F.ASUSProductRegistrationProgram"
    "B9ECED6F.MyASUS"
    "B9ECED6F.eManual"
    "BD9B8345.AlbumbySony*"
    "BD9B8345.MusicbySony*"
    "BD9B8345.Socialife*"
    "BD9B8345.VAIOCare*"
    "BD9B8345.VAIOMessageCenter*"
    "C27EB4BA.DropboxOEM"
    "COMPALELECTRONICSINC.AlienwareOSDKits"
    "COMPALELECTRONICSINC.AlienwareTypeCaccessory"
    "COMPALELECTRONICSINC.Alienwaredockingaccessory"
    "ChaChaSearch.ChaChaPushNotification*"
    "ClearChannelRadioDigital.iHeartRadio*"
    "CrackleInc.Crackle*"
    "CyberLinkCorp.ac.AcerCrystalEye*"
    "CyberLinkCorp.ac.SocialJogger*"
    "CyberLinkCorp.hs.YouCamforHP*"
    "CyberLinkCorp.id.PowerDVDforLenovoIdea*"
    "D52A8D61.FarmVille2CountryEscape*"
    "D5EA27B7.Duolingo-LearnLanguagesforFree*"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials*"
    "DailymotionSA.Dailymotion*"
    "DellInc.AlienwareCommandCenter"
    "DellInc.AlienwareCustomerConnect"
    "DellInc.AlienwareProductRegistration"
    "DellInc.DellCustomerConnect"
    "DellInc.DellHelpSupport"
    "DellInc.DellPowerManager"
    "DellInc.DellProductRegistration"
    "DellInc.DellShop"
    "DellInc.DellSupportAssistforPCs"
    "DolbyLaboratories.DolbyAccess*"
    "DolbyLaboratories.DolbyAtmosSoundSystem"
    "Drawboard.DrawboardPDF*"
    "DriverToaster*"
    "E046963F.LenovoCompanion*"
    "E046963F.LenovoSupport*"
    "E0469640.CameraMan*"
    "E0469640.DeviceCollaboration*"
    "E0469640.LenovoRecommends*"
    "E0469640.YogaCameraMan*"
    "E0469640.YogaPhoneCompanion*"
    "E0469640.YogaPicks*"
    "ESPNInc.WatchESPN*"
    "EncyclopaediaBritannica.EncyclopaediaBritannica*"
    "Evernote.Evernote"
    "Evernote.Skitch*"
    "F5080380.ASUSPowerDirector*"
    "Facebook.317180B0BB486"
    "Facebook.Facebook"
    "Facebook.InstagramBeta*"
    "FilmOnLiveTVFree.FilmOnLiveTVFree*"
    "Fingersoft.HillClimbRacing"
    "FingertappsInstruments*"
    "FingertappsOrganizer*"
    "Flipboard.Flipboard*"
    "FreshPaint*"
    "GAMELOFTSA.Asphalt8Airborne*"
    "GAMELOFTSA.SharkDash*"
    "GameGeneticsApps.FreeOnlineGamesforLenovo*"
    "GettingStartedwithWindows8*"
    "GoogleInc.GoogleSearch"
    "HPConnectedMusic*"
    "HPConnectedPhotopoweredbySnapfish*"
    "HPRegistration*"
    "HuluLLC.HuluPlus*"
    "JigsWar*"
    "K-NFBReadingTechnologiesI.BookPlace*"
    "KasperskyLab.KasperskyNow*"
    "KeeperSecurityInc.Keeper"
    "KindleforWindows8*"
    "LenovoCorporation.LenovoID*"
    "LenovoCorporation.LenovoSettings*"
    "MAGIX.MusicMakerJam*"
    "McAfeeInc.01.McAfeeSecurityAdvisorforDell"
    "McAfeeInc.05.McAfeeSecurityAdvisorforASUS"
    "MobileFileExplorer*"
    "MusicMakerJam*"
    "NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*"
    "NAVER.LINEwin8*"
    "NBCUniversalMediaLLC.NBCSportsLiveExtra*"
    "Nordcurrent.CookingFever"
    "PandoraMediaInc.29680B314EFC2"
    "PinballFx2*"
    "Playtika.CaesarsSlotsFreeCasino*"
    "Priceline"
    "PricelinePartnerNetwork.Priceline.comTheBestDealso"
    "PublicationsInternational.iCookbookSE*"
    "RandomSaladGamesLLC.GinRummyProforHP*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience"
    "ShazamEntertainmentLtd.Shazam*"
    "SonicWALL.MobileConnect"
    "SpotifyAB.SpotifyMusic"
    "SymantecCorporation.NortonStudio*"
    "TelegraphMediaGroupLtd.TheTelegraphforLenovo*"
    "TheNewYorkTimes.NYTCrossword*"
    "ThumbmunkeysLtd.PhototasticCollage*"
    "ToshibaAmericaInformation.ToshibaCentral*"
    "TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*"
    "TuneIn.TuneInRadio*"
    "UptoElevenDigitalSolution.mysms-Textanywhere*"
    "Vimeo.Vimeo*"
    "Weather.TheWeatherChannelforHP*"
    "Weather.TheWeatherChannelforLenovo*"
    "WildTangentGames*"
    "WildTangentGames.63435CFB65F55"
    "WinZipComputing.WinZipUniversal*"
    "XINGAG.XING"
    "XeroxCorp.PrintExperience"
    "YouSendIt.HighTailForLenovo*"
    "ZinioLLC.Zinio*"
    "eBayInc.eBay*"
    "esobiIncorporated.newsXpressoMetro*"
    "fingertappsASUS.FingertappsInstrumentsrecommendedb*"
    "fingertappsASUS.JigsWarrecommendedbyASUS*"
    "fingertappsasus.FingertappsOrganizerrecommendedbyA*"
    "flaregamesGmbH.RoyalRevolt2*"
    "king.com*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "sMedioforHP.sMedio360*"
    "sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*"
    "toolbar*"
    "zuukaInc.iStoryTimeLibrary*"
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"
    "*Minecraft*"
    "*Royal Revolt*"
)

# Add services here if you'd like
$systemServices = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (Comment this if using sysprep)
    "HomeGroupListener"                        # HomeGroup Listener
    "HomeGroupProvider"                        # HomeGroup Provider
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    "RemoteRegistry"                           # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    "WbioSrvc"                                 # Windows Biometric Service
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
)

# Tasks
$defenderTasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
)

# IP's and hosts
$msIPs = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"
    "65.55.108.23"
    "64.4.54.254"
)

$telemetryDomains = @(
    "184-86-53-99.deploy.static.akamaitechnologies.com"
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    "a978.i6g1.akamai.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "ads.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "a-msedge.net"
    "any.edge.bing.com"
    "a.rad.msn.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "bingads.microsoft.com"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "compatexchange.cloudapp.net"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "corp.sts.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "ipv6.msftncsi.com"
    "ipv6.msftncsi.com.edgesuite.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "onesettings-db5.metron.live.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    "settings-win.data.microsoft.com"
    "sls.update.microsoft.com.akadns.net"
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "ssw.live.com"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.appex.bing.net:443"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "www.msftncsi.com"
    "fe2.update.microsoft.com.akadns.net"
    "s0.2mdn.net"
    "statsfe2.update.microsoft.com.akadns.net",
    "survey.watson.microsoft.com"
    "view.atdmt.com"
    "watson.microsoft.com",
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "m.hotmail.com"
)

$telemetrySkypeDomains = @(
    "ui.skype.com",
    "pricelist.skype.com"
    "apps.skype.com"
    "s.gateway.messenger.live.com"
    "c.msn.com"
)
	
# Files
$etcHosts = "$env:systemroot\System32\drivers\etc\hosts"

# Functions
function mkdir-forceful($path) {
    if (!(Test-Path $path)) {
        New-Item -ItemType Directory -Force -Path $path
    }
}

function show-message($info) {
    Write-Host -foreground "magenta" $info
}

function show-warning($info) {
    Write-Host -foreground "red" -background "DarkGray" $info
}

# Please run as admin. Don't be a moron.
$userIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userObject = New-Object Security.Principal.WindowsPrincipal($userIdentity)
if (-not $userObject.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "PLEASE RUN AS ADMIN"
    exit
}

# Removing most Windoze Apps and forcing "Cloud Content" to never come back
If ($RemoveApps -eq '1') {
    show-message "Removing built-in apps"
    foreach ($x in $applist) {
        Get-AppxPackage -Name $x -AllUsers | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | where DisplayName -Like $x | Remove-AppxProvisionedPackage -Online
    }
    show-message "Removing extraneous apps"
    foreach ($x in $extraAppList) {
        Get-AppxPackage -Name $x -AllUsers | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | where DisplayName -Like $x | Remove-AppxProvisionedPackage -Online
    }
    show-message "Disabling Windows Consumer Features and Tips"
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1

    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" 0
}

If ($RemoveOneDrive -eq '1') {
    # We need to kill the processes first
    show-message "Killing Onedrive"
    taskkill.exe /F /IM "OneDrive.exe"
    taskkill.exe /F /IM "explorer.exe"

    # Delete the pesky setup files
    show-message "Delete Onedrive Setup"
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }

    show-message "Deleting extra onedrive stuff"
    rm -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
    rm -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
    rm -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp"

    # GP OneDrive Disable
    show-message "Disabling OneDrive in Group Policy"
    mkdir-forceful "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
    sp "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

    # Create powershell drive for the classes root registry
    # Making it so the sidebar doesn't have it anymore
    show-message "Disabling OneDrive Sidebar"
    New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
    mkdir-forceful "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    mkdir-forceful "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    sp "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    sp "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    Remove-PSDrive "HKCR"

    # Preventing the first time login hook and startmenu entry
    show-message "Disabling OneDrive First Login Hook"
    reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
    reg unload "hku\Default"
    rm -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
}

# WARNING: If you remove the store, you can no longer install Windows Apps. If you actually
#          want one of the apps that I'm removing, comment it above before you remove the
#          store. IT IS EXTREMELY DIFFICULT TO UNDO THIS.
#          Don't say I didn't warn you.
If ($RemoveStore -eq '1') {
    show-warning "WARNING: Deleting the Windows Store"
    Get-AppxPackage *WindowsStore* | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | where DisplayName -Like *WindowsStore* | Remove-AppxProvisionedPackage -Online
}

if ($DisableServices -eq '1') {
    foreach ($x in $systemServices) {
        Get-Service -Name $x | Set-Service -StartupType Disabled
    }
}

# You would be an idiot to leave this garbage enabled
If ($DisableDefender -eq '1') {
    # Disable the annoying tray
    show-message "Removing Defender Tray"
    rp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0
    rp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "SecurityHealth" -ea 0

    # There are task scheduler things to turn off
    show-message "Removing Defender Scheduled Tasks"
    foreach ($x in $tasks) {
        $parts = $x.split('\')
        $name = $parts[-1]
        $path = $parts[0..($parts.length-2)] -join '\'

        Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
    }
    # GP
    show-message "Defender Group Policy Settings"
    mkdir-forceful "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
    mkdir-forceful "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
    sp "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
    sp "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
    sp "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1

    # Disable services
    # TODO: I think I need to change the ownership of these keys before changing them - This doesn't seem to work.
    show-message "Defender Disable Service"
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
    sp "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3

    # Apparently there's a context menu. Found that out today.
    show-message "Defender context menu"
    si "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""
}

# This basically applies "true mouse", or MarkC's "Mouse Acceleration Fix"
# http://donewmouseaccel.blogspot.com/2010/03/markc-windows-7-mouse-acceleration-fix.html
If ($EnableTrueMouse -eq '1') {
    show-message "Applying True Mouse"
    sp "HKCU:\Control Panel\Mouse" "MouseSensitivity" "10"
    sp "HKCU:\Control Panel\Mouse" "MouseSpeed" "0"
    sp "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0"
    sp "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0"
    sp "HKCU:\Control Panel\Mouse" "SmoothMouseXCurve" ([byte[]](0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
    sp "HKCU:\Control Panel\Mouse" "SmoothMouseYCurve" ([byte[]](0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))

    # Stops the mouse from hiding
    sp "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x9e,
    0x1e, 0x06, 0x80, 0x12, 0x00, 0x00, 0x00))
}

if ($UsabilityFeatures -eq 1) {
    # Disable gamebar
    show-message "Disabling gamebar"
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0
    # Disable sticky keys
    show-message "Disabling sticky keys"
    sp "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
    # Disable ease of access
    show-message "Disabling ease of access"
    sp "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
    sp "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"
    # Sync Provider Explorer
    show-message "Disable sync provider"
    sp "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0
    # Disable all suggestions
    show-message "Disable suggestions"
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
    # Disable update seeding
    show-message "Disable Windows Update Seeding"
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
    # Disable cortana
    show-message "Disabling cortana by policy"
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
    if ($DisableDriverUpdates -eq 1) {
        # Disable driver updates
        show-warning "Disabling automatic driver updates"
        sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0
    }
    # Disable people bar
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" 0
    # Remove "modern sharing" - original value is {e2bf9676-5f8f-435c-97eb-11607a5bedf7}
    ri 'HKLM:\SOFTWARE\Classes\`*\shellex\ContextMenuHandlers\ModernSharing'

    # Making brand new users have similar settings from above and others
    Write-Host "Attempting to disable all new users from getting Content Delivery Apps (does not affect current user)"
    reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
    sp "Registry::HKU\Default_User\Control Panel\Accessibility\StickyKeys" "Flags" 506
    sp "Registry::HKU\Default_User\Control Panel\Accessibility\Keyboard Response" "Flags" 122
    sp "Registry::HKU\Default_User\Control Panel\Accessibility\ToggleKeys" "Flags" 58
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0
    sp "Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" 0
    reg unload HKU\Default_User
}

if ($DisableTelemetry -eq 1) {
    show-message "Disable Telemetry"
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

    if ($DisableTelemetryEtcHosts -eq 1) {
        show-message "Disable Telemetry in \etc\hosts"
        foreach ($x in $telemetryDomains) {
        if (-Not (Select-String -Path $etcHosts -Pattern $x)) {
            echo "0.0.0.0 $x" | Out-File -Encoding ASCII -Append $etcHosts
            }
        }
    }

    # If you're one of those assholes who still use skype, make sure it's "1"
    if ($EnableSkype -eq 0) {
        show-message "Disable Skype Telemetry in \etc\hosts"
        foreach ($x in $telemetrySkypeDomains) {
        if (-Not (Select-String -Path $etcHosts -Pattern $x)) {
            echo "0.0.0.0 $x" | Out-File -Encoding ASCII -Append $etcHosts
            }
        }
    }
}

if ($PrivacyTweaks -eq 1) {
    foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
    mkdir-forceful "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    sp "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
    foreach ($x in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
        if ($x.PSChildName -EQ "LooselyCoupled") {
            continue
        }
        sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $x.PSChildName) "Type" "InterfaceClass"
        sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $x.PSChildName) "Value" "Deny"
        sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $x.PSChildName) "InitialAppValue" "Unspecified"
    }

    sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
    mkdir-forceful "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
}

if ($ImportLayout -eq 1) {
    Copy-Item C:\Programs\layout.xml C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\CustomLayout.xml
    Import-StartLayout -LayoutPath C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\CustomLayout.xml -MountPath $env:SystemDrive\
}

if ($RestartComputer -eq 1) {
    show-warning "Your system will reboot in 5 seconds"
    sleep 5
    Restart-Computer
} Else {
    show-message "Starting Explorer"
    start "explorer.exe"
}
