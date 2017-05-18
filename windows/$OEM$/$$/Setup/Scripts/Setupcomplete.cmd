@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
choco install firefox 7zip notepadplusplus -y
@powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Programs\win10clean.ps1"
