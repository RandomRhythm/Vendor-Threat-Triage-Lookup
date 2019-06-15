' Imports IP To Country IPv4 data into VTTL database. https://db-ip.com/db/lite.php or https://db-ip.com/db/ip-to-country
Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
CurrentDirectory = GetFilePath(wscript.ScriptFullName)
Dim strDatabasePath: strDatabasePath = CurrentDirectory & "\vttl.db"

  Dim oCS     : oCS       = "Driver={SQLite3 ODBC Driver};Database=" & strDatabasePath & ";Version=3;"
  Dim oCNCT   : Set oCNCT = CreateObject( "ADODB.Connection" )



  
wscript.echo "Please open the IP To Country CSV to import"
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
			if instr(strCSVData, ":") then exit do 'IPV6 is not supported :-(
			arrayCSV = split(strCSVData, ",")
			startRage = Dotted2LongIP(arrayCSV(0))
			endRange = Dotted2LongIP(arrayCSV(1))
			countryCode = arrayCSV(ubound(arrayCSV)) 'last item is the country code in both IP to Country databases
			'msgbox startRage & "|" & endRange & "|" &  countryCode
			'if RangeCheck(startRage) <> endRange then 'not good for loading data quickly
				SaveRange startRage, endRange, countryCode
			'end if

		end if
	end if
 loop
 

createIndices

end if





Function RangeCheck(intStartRange)
Dim strTmpPubDomains

sSQL = "select EndRange from DB_IP where StartRange = ? " 
RangeCheck = ReturnSQLiteItem(sSQL, int(intStartRange), "EndRange", 201) 
 
end function




Function ReturnSQLiteItem(sSQL, strQueryItem, strReturnName, intType)'129 - string   201 - long

'msgbox sSQL & "|" &  strQueryItem & "|" &  strReturnName
Set Recordset = CreateObject("ADODB.Recordset")
Set cmd = Nothing
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
   set objparameter0 = cmd.createparameter("@VarQueryItem", intType, 1, len(strQueryItem),strQueryItem)

         cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
  Recordset.Open cmd

  If not Recordset.EOF Then 
    on error resume next
    ReturnSQLiteItem = Recordset.fields.item(strReturnName)
    on error goto 0
  end if
    Set cmd = Nothing
    Set objparameter0 = Nothing
    Recordset.close
    Set Recordset = Nothing
End Function


Sub SaveRange(strStartRange, strEndRange, strCountryCode)
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
sSQL = "INSERT INTO DB_IP(StartRange, EndRange,CountryCode) VALUES(?, ?, ?)"

  set objparameter0 = cmd.createparameter("@StartRange", 201, 1, len(strStartRange),strStartRange)
  set objparameter1 = cmd.createparameter("@EndRange", 201, 1, len(strEndRange),strEndRange)
  set objparameter3 = cmd.createparameter("@CountryCode", 129, 1, len(strCountryCode),strCountryCode)

    cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
    if objparameter1 <> Empty then 
      cmd.Parameters.Append objparameter1
    end if
	if objparameter3 <> Empty then 
      cmd.Parameters.Append objparameter3
    end if
    on error resume next
    cmd.execute
    if err.number = -2147467259 then
      'UNIQUE constraint failed
    elseif err.number <> 0 then 
      objShellComplete.popup "Error #" & err.number & " - " & err.description & vbcrlf & vbcrlf & "Problem writting to DB_IP:" & vbcrlf & strStartRange & "|" & strCountryCode, 30
    end if
    on error goto 0
    Set cmd = Nothing
end sub


Public Function Dotted2LongIP(DottedIP) 'http://www.freevbcode.com/ShowCode.asp?ID=938
    ' errors will result in a zero value
    On Error Resume Next

    Dim i, pos
    Dim PrevPos, num

    ' string cruncher
    For i = 1 To 4
        ' Parse the position of the dot
        pos = InStr(PrevPos + 1, DottedIP, ".", 1)

        ' If its past the 4th dot then set pos to the last
        'position + 1

        If i = 4 Then pos = Len(DottedIP) + 1

       ' Parse the number from between the dots

        num = Int(Mid(DottedIP, PrevPos + 1, pos - PrevPos - 1))

        ' Set the previous dot position
        PrevPos = pos

        ' No dot value should ever be larger than 255
        ' Technically it is allowed to be over 255 -it just
        ' rolls over e.g.
         '256 => 0 -note the (4 - i) that's the 
         'proper exponent for this calculation


      Dotted2LongIP = ((num Mod 256) * (256 ^ (4 - i))) + _
         Dotted2LongIP

    Next
    on error goto 0

End Function



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
    sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='DB_IP'"
    
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
		CreateTable    
	else
		theAnswer = msgbox ("DB_IP table already exists. Do you wish to replace the table with a new version?")
		if theAnswer = VbYes then
			DropTable
			CreateTable
		else
		
		end if
	end if
	
	  boolConnectSuccess = True
end function


sub DropTable
sSQL =  "DROP TABLE DB_IP"
oCNCT.Execute sSQL

end sub


Sub CreateTable
wscript.echo "Table DB_IP does not exist. Attempting to create table"
sSQL =  "CREATE TABLE DB_IP (StartRange INTEGER,EndRange INTEGER,CountryCode TEXT)"
oCNCT.Execute sSQL
end sub


Sub createIndices
sSQL = "CREATE INDEX StartRange on DB_IP (StartRange);"
  oCNCT.Execute sSQL
  sSQL = "CREATE INDEX EndRange on DB_IP (EndRange);"
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