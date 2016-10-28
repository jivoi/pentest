# Install Wine, python and pyinstaller in kali
# apt-get install -y wine
# wget https://www.python.org/ftp/python/2.7.12/python-2.7.12.msi
# wine msiexec /i python-2.7.12.msi /L*v log.txt
# cd ~/.wine/drive_c/Python27
# wine python.exe Scripts/pip.exe install pyinstaller
# wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile sep_exploit.py

wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile $1
