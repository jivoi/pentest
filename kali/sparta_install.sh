#!/bin/sh
apt-get install -y python-pyside xsltproc

cd /opt/
git clone https://github.com/SECFORCE/sparta.git

cat > ./sparta_py.patch <<'_EOF'
--- sparta.py   2017-03-30 17:12:18.045457176 +0300
+++ sparta2.py  2017-03-30 17:14:21.125457176 +0300
@@ -18,10 +18,10 @@
 except:
        print "[-] Import failed. Elixir library not found. \nTry installing it with: apt-get install python-elixir"
        exit(0)
-try:
-       from PyQt4 import QtGui, QtCore, QtWebKit
+try:
+       from PySide import QtWebKit
 except:
-       print "[-] Import failed. PyQt4 library not found. \nTry installing it with: apt-get install python-qt4"
+       print "[-] Import failed. QtWebkit library not found. \nTry installing it with: apt-get install python-pyside.qtwebkit"
        exit()

 from app.logic import *
_EOF

patch sparta.py sparta_py.patch

cat > ./ui_view_py.patch <<'_EOF'
--- ui/view.py  2017-03-30 17:24:41.805457176 +0300
+++ ui/view2.py 2017-03-30 17:27:55.853457176 +0300
@@ -13,7 +13,7 @@

 import sys, os, ntpath, signal, re                                                                             # for file operations, to kill processes and for regex
 from PyQt4.QtCore import *                                                                                             # for filters dialog
-from PyQt4 import QtWebKit                                                                                             # to show html code (help menu)
+from PySide import QtWebKit
 from ui.gui import *
 from ui.dialogs import *
 from ui.settingsdialogs import *
@@ -50,7 +50,7 @@
                self.settingsWidget = AddSettingsDialog(self.ui.centralwidget)
                self.helpWidget = QtWebKit.QWebView()
                self.helpWidget.setWindowTitle('SPARTA Help')
-               self.helpWidget.load(QUrl('./doc/help.html'))
+               self.helpWidget.load('./doc/help.html')

                self.ui.HostsTableView.setSelectionMode(1)                                              # disable multiple selection
                self.ui.ServiceNamesTableView.setSelectionMode(1)
_EOF

patch ui/view.py ui_view_py.patch

python sparta.py