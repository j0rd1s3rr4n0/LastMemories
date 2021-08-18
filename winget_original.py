# Winget Using Python
"""
# Fases:
# 1 - winget install 
# 2 - winget source update
# 3 - winget upgrade

 comando "winget search" deimitador espacio 3 columnas generales de las cuales las 2 ultimas no
varian pero la primera puede generar infinitas tablas

Es decir para cojer el nombre principal se usara [0:(len(linea)-2)]
cmd /c winget search > asd.txt

YouTube Downloader GUI                 jely2002.youtube-dl-gui            2.2.2
Evernote                               evernote.evernote                  10.17.8
qBittorrent Enhanced Edition           c0re100.qBittorrent-Enhanced-Edit… 4.3.7.10
calibre                                calibre.calibre                    5.25.0q
Wireshark                              WiresharkFoundation.Wireshark      3.4.7.0
Voicemod                               Voicemod.Voicemod                  2.17.0.2
VLC media player                       VideoLAN.VLC                       3.0.16
VirusTotal Uploader                    VirusTotal.VirusTotalUploader      2.2
Steam                                  Valve.Steam                        2.10.91.91
Unity                                  UnityTechnologies.Unity            2021.1.16f1
Unity Hub                              UnityTechnologies.UnityHub         2.4.5
Tor Browser                            TorProject.TorBrowser              10.5.4
FileZilla Client                       TimKosse.FileZillaClient           3.55.1
FileZilla Server                       TimKosse.FileZillaServer           beta 0.9.60
TeamViewer                             TeamViewer.TeamViewer              15.20.6
TeamViewer Host                        TeamViewer.TeamViewerHost          15.20.6
TeamViewerQS                           TeamViewer.TeamViewerQS            Latest
Camtasia                               TechSmith.Camtasia                 21.0.5.31722
Telegram Desktop                       Telegram.TelegramDesktop           2.9.2
Sublime Text 3                         SublimeHQ.SublimeText.3            3.2.2
Sublime Text 4                         SublimeHQ.SublimeText.4            4.0.0.411300
Autopsy                                SleuthKit.Autopsy                  4.19.1
Clownfish Voice Changer                SharkLabs.ClownfishVoiceChanger    1.47.0.0
Sandboxie Classic                      SandboxiePlus.SandboxieClassic     5.51.3
Sandboxie-Plus                         SandboxiePlus.SandboxiePlus        0.9.3
Rufus                                  Rufus.Rufus                        3.13.1730.0
VNC Server                             RealVNC.VNCServer                  6.7.4.43891
VNC Viewer                             RealVNC.VNCViewer                  6.21.406.44671
WinRAR                                 RARLab.WinRAR                      6.02.0
Python 2                               Python.Python.2                    2.7.18150
Python 3                               Python.Python.3                    3.9.6150.0
PuTTY                                  PuTTY.PuTTY                        0.76.0.0
ProtonVPN                              ProtonTechnologies.ProtonVPN       1.22.2
Java                                   Oracle.JavaRuntimeEnvironment      8.0.3010.9
4K Video Downloader                    OpenMedia.4KVideoDownloader        4.17.1.4410
OBS Studio                             OBSProject.OBSStudio               27.0.1
Mozilla Firefox                        Mozilla.Firefox                    91.0
Visual Studio Enterprise 2019          Microsoft.VisualStudio.2019.Enter… 16.11.0
Malwarebytes                           Malwarebytes.Malwarebytes          4.4.4.126
LibreOffice                            LibreOffice.LibreOffice            7.1.5.2
Krita                                  KDE.Krita                          4.4.7
Backup and Sync from Google            Google.BackupAndSync               3.55.3625.9414
Google Chrome                          Google.Chrome                      92.0.4515.131
GitHub Desktop                         GitHub.GitHubDesktop               2.9.0
AIDA64 Engineer                        FinalWire.AIDA64Engineer           6.33
AIDA64 Extreme                         FinalWire.AIDA64Extreme            6.33
Advanced IP Scanner                    Famatech.AdvancedIPScanner         2.5.3850
Advanced Port Scanner                  Famatech.AdvancedPortScanner       2.5.3869
Discord                                Discord.Discord                    1.0.9002
CrystalDiskInfo                        CrystalDewWorld.CrystalDiskInfo    8.12.5
CrystalDiskInfo Kurei Kei Edition      CrystalDewWorld.CrystalDiskInfo.K… 8.12.5
CrystalDiskInfo Shizuku Edition        CrystalDewWorld.CrystalDiskInfo.S… 8.12.5
CrystalDiskMark                        CrystalDewWorld.CrystalDiskMark    8.0.4
CrystalDiskMark Shizuku Edition        CrystalDewWorld.CrystalDiskMark.S… 8.0.4
CrystalDiskMark Tsukumo Tokka Edition  CrystalDewWorld.CrystalDiskMark.T… 8.0.4
K-Lite Codec Pack 16.3.5 Basic         CodecGuide.K-LiteCodecPackBasic    16.3.5
K-Lite Codec Pack 16.3.5 Full          CodecGuide.K-LiteCodecPackFull     16.3.5
K-Lite Mega Codec Pack                 CodecGuide.K-LiteCodecPackMega     16.3.0
K-Lite Codec Pack 16.3.5 Standard      CodecGuide.K-LiteCodecPackStandard 16.3.5
Battle.Net                             Blizzard.BattleNet                 1.22.0.12040
Bitwarden                              Bitwarden.Bitwarden                1.27.1
Binance                                BinanceTech.Binance                1.20.1
Any.do                                 Anydo.Anydo                        4.2.157
OpenOffice                             Apache.OpenOffice                  4.1.10
XAMPP                                  ApacheFriends.Xampp                8.0.9-0
AnyDesk                                AnyDeskSoftwareGmbH.AnyDesk        ad 6.3.2
AnyDesk MSI                            AnyDeskSoftwareGmbH.AnyDeskMSI     6.3.2
7-Zip                                  7zip.7zip                          19.00.00.0
"""

import os
import time
import getpass
import pandas as pd
import subprocess

def Testing():
	# echo '' > %temp%\error788.txt
	# Extract Packages
	systemuser = getpass.getuser()
	archivo = 'C:\\Users\\'+str(systemuser)+'\\AppData\\Local\\Temp\\paquetes_python.txt'
	try:
		os.remove(archivo)
	except:
		os.system('fsutil file createnew '+'C:\\Users\\'+str(systemuser)+'\\AppData\\Local\\Temp\\paquetes_python.txt 0')
	os.system('fsutil file createnew '+'C:\\Users\\'+str(systemuser)+'\\AppData\\Local\\Temp\\paquetes_python.txt 0')
	print('Este proceso puede tardar 2 min aprox ...')
	os.system('winget search > '+archivo)
	time.sleep(0)
	print('run')
	runing = True
	print('run')
	fake_line = ''
	while runing == True:
		result = subprocess.getoutput('tasklist | findstr "AppInstaller" || cls')
		print(result)
		if "AppInstaller" in result:
			print('1')
		else:
			ruta = "C:\\Users\\"+str(systemuser)+"\\AppData\\Local\\Temp\\paquetes_python.txt"
			#f = open(ruta,"r",encoding="utf8")
			print(ruta)
			with open(ruta,encoding="utf8") as fp:
				line = fp.readline()
				if fake_line != line:
					cnt = 1
					while line:
						print("{}".format(line.strip()))
						fake_line = line
						a = line
						line = fp.readline()
						a = fp.readline()
						# Extract Program Name
						a = a.split(" ")
						a = list(pd.unique(a))
						if '--' in a:
							a.remove('--')
						#a.pop(0)
						s = 0						
						new = []
						for elements in a:
							if len(elements) > 3:
								if elements != '':
									#print('#')
									#print(a)
									rdr = str(a[s])
									new.append(rdr)
									#new.pop(0)
									#print('$')
									#print(len(new))
						newstringName = ''.join(map(str,new[0:]))
						newstringPackage = ''.join(map(str,new[(len(new)-3):(len(new)-2)]))
						newstringVersion = ''.join(map(str,new[(len(new)-2):len(new)-1]))
						#print(newstringName,'//',newstringPackage,'//',newstringVersion)
						# Installing
						if newstringName != '':
							print(newstringName)
							installstring = ('cmd /c winget install "%s"' % newstringName)
							#	#os.system(installstring)
							#print(installstring)
						s+=1
					cnt+=1
						

			fp.close()
		runing = False
	a =[]
def main():
	Testing()

if __name__ == '__main__':
    main()