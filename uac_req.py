import ctypes, sys
# net user Administrador /active:yes
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    # Code of your program here
    print('I\'m ROOT')
else:
    # Re-run the program with admin rights
    ctypes.windll.Shell32.ShellExecuteW(None, "runas", sys.executable, 0,'C:\\Users\\Admin\\Desktop\\uac_req.py', 1)
    print('I\'m ROOT NOW')