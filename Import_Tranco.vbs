' Imports Tranco list into VTTL database. 
Dim boolCreateIndex

'config section
boolCreateIndex = True 'VTTL will create the index on first run. Setting to false allows the DB to be distributed via GitHub
'end config section

Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
CurrentDirectory = GetFilePath(wscript.ScriptFullName)
Dim strDatabasePath: strDatabasePath = CurrentDirectory & "\vttl.db"

  Dim oCS     : oCS       = "Driver={SQLite3 ODBC Driver};Database=" & strDatabasePath & ";Version=3;"
  Dim oCNCT   : Set oCNCT = CreateObject( "ADODB.Connection" )



  
wscript.echo "Please open the Tranco list top-1m.csv"
OpenFilePath1 = SelectFile( )

if OpenFilePath1 = "" then 
	wscript.echo "No file path specified. Script will exit."
	wscript.quit
end if
SQLTestConnect strDatabasePath

Dim strSigCheckOut
Dim IntColumnCount


if objFSO.fileexists(OpenFilePath1) then
  Set objFile = objFSO.OpenTextFile(OpenFilePath1)

 Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strCSVData = objFile.ReadLine 
        on Error GoTo 0
		if instr(strCSVData, ",") then
			arrayCSV = split(strCSVData, ",")
			TScore = arrayCSV(0)
			TDomain = arrayCSV(1)
			SaveDomain TDomain, TScore
		end if
	end if
 loop
 if boolCreateIndex = True then createIndices
end if

msgbox "Tranco list import complete."

Sub SaveDomain(strTmpDomain, IntDomainVal)
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
sSQL = "INSERT INTO Tranco(T_Domain, T_Score) VALUES(?, ?)"

  set objparameter0 = cmd.createparameter("@T_Domain", 129, 1, len(strTmpDomain),strTmpDomain)
  set objparameter1 = cmd.createparameter("@T_Score", 201, 1, len(IntDomainVal),IntDomainVal)

     Set cmd = Nothing
      Set cmd = createobject("ADODB.Command")
    cmd.ActiveConnection = oCNCT
    cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
    if objparameter1 <> Empty then 
      cmd.Parameters.Append objparameter1
    end if
    on error resume next
    cmd.execute
    if err.number = -2147467259 then
      'UNIQUE constraint failed
    elseif err.number <> 0 then 
      objShellComplete.popup "Error #" & err.number & " - " & err.description & vbcrlf & vbcrlf & "Problem writting to PublisherDomains:" & vbcrlf & strPublisher & "|" & strTmpPubDomains, 30
    end if
    on error goto 0
    Set cmd = Nothing
end sub


Function SQLTestConnect(strDatabasePath)
Set Recordset = CreateObject("ADODB.Recordset")
boolConnectSuccess = True
on error resume next
oCNCT.Open oCS
if err.number <> 0 then 

  SQLTestConnect = False

  'SQLite database exists check
	msgbox err.message
	on error goto 0
	if instr(strDatabasePath, "\") > 0 then
		tmpDbPath = GetFilePath(strDatabasePath)
		if objfso.folderexists(tmpDbPath) = False then
			msgbox "Folder path " & chr(34) & tmpDbPath & chr(34) & " does not exist. Please create the directory or change the location of the database."
			exit function
		end if
	end if
	theAnswer = msgbox ("Unable to connect to database. Ensure SQLite 3 driver is installed and database file path (" & strDatabasePath & ") is accessible." & vbcrlf & vbcrlf & "Note: We typically install this one for 64-bit computers:" & vbcrlf & _
 "http://www.ch-werner.de/sqliteodbc/sqliteodbc_w64.exe" & vbcrlf & vbcrlf & "Would like like to open a browser to download the file?",vbYesNo, "VTTL Question")
	if theAnswer = VbYes then
		Set objShll = CreateObject("Shell.Application")
		objShll.ShellExecute "http://www.ch-werner.de/sqliteodbc/"
		msgbox "Note: We typically install this one for 64-bit computers:" & vbcrlf & _
 "http://www.ch-werner.de/sqliteodbc/sqliteodbc_w64.exe"
		msgbox "Close this dialog if you have completed the driver installation to restart VTTL."
		objShellComplete.run "wscript.exe " & chr(34) & CurrentDirectory & "\" & wscript.ScriptName & Chr(34) & " " & strQueueParameters 
		wscript.quit
	end if

   
  boolConnectSuccess = False
  exit function
end if
on error goto 0

    Dim sSQL
    sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='Tranco'"
    
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
		CreateTable    
	else
		theAnswer = msgbox ("Tranco table already exists. Do you wish to replace the table with a new version?")
		if theAnswer = VbYes then
			DropTable
			CreateTable
		else
		
		end if
	end if
	
	  boolConnectSuccess = True
end function


sub DropTable
sSQL =  "DROP TABLE Tranco"
oCNCT.Execute sSQL
end sub


Sub CreateTable
wscript.echo "Table Tranco does not exist. Attempting to create table"
sSQL =  "CREATE TABLE Tranco (T_Domain TEXT, T_Score INTEGER)"
oCNCT.Execute sSQL
end sub


Sub createIndices
sSQL = "CREATE INDEX TDomain on Tranco (T_Domain);"
  oCNCT.Execute sSQL
end sub


Function SelectFile( )
    ' File Browser via HTA
    ' Author:   Rudi Degrande, modifications by Denis St-Pierre and Rob van der Woude
    ' Features: Works in Windows Vista and up (Should also work in XP).
    '           Fairly fast.
    '           All native code/controls (No 3rd party DLL/ XP DLL).
    ' Caveats:  Cannot define default starting folder.
    '           Uses last folder used with MSHTA.EXE stored in Binary in [HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32].
    '           Dialog title says "Choose file to upload".
    ' Source:   http://social.technet.microsoft.com/Forums/scriptcenter/en-US/a3b358e8-15&?lig;-4ba3-bca5-ec349df65ef6

    Dim objExec, strMSHTA, wshShell

    SelectFile = ""

    ' For use in HTAs as well as "plain" VBScript:
    strMSHTA = "mshta.exe ""about:" & "<" & "input type=file id=FILE>" _
             & "<" & "script>FILE.click();new ActiveXObject('Scripting.FileSystemObject')" _
             & ".GetStandardStream(1).WriteLine(FILE.value);close();resizeTo(0,0);" & "<" & "/script>"""
    ' For use in "plain" VBScript only:
    ' strMSHTA = "mshta.exe ""about:<input type=file id=FILE>" _
    '          & "<script>FILE.click();new ActiveXObject('Scripting.FileSystemObject')" _
    '          & ".GetStandardStream(1).WriteLine(FILE.value);close();resizeTo(0,0);</script>"""

    Set wshShell = CreateObject( "WScript.Shell" )
    Set objExec = wshShell.Exec( strMSHTA )

    SelectFile = objExec.StdOut.ReadLine( )

    Set objExec = Nothing
    Set wshShell = Nothing
End Function


Function GetFilePath (ByVal FilePathName)
found = False

Z = 1
Do While found = False and Z < Len((FilePathName))

 Z = Z + 1

         If InStr(Right((FilePathName), Z), "\") <> 0 And found = False Then
          mytempdata = Left(FilePathName, Len(FilePathName) - Z)
          
             GetFilePath = mytempdata

             found = True

        End If      

Loop

end Function



found = False

Z = 1

Do While found = False and Z < Len((FilePathName))

 Z = Z + 1

         If InStr(Right((FilePathName), Z), "\") <> 0 And found = False Then
          mytempdata = Left(FilePathName, Len(FilePathName) - Z)
          
             GetFilePath = mytempdata

             found = True

        End If      

Loop