'Vendor Threat Triage Lookup (VTTL) script 'VTTL v 8.2.1.6 - Don't pause processing with message box for odd length hashes

'Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.

'This program is free software: you can redistribute it and/or modify
'it under the terms of the GNU General Public License as published by
'the Free Software Foundation, either version 3 of the License, or
'(at your option) any later version.

'This program is distributed in the hope that it will be useful,
'but WITHOUT ANY WARRANTY; without even the implied warranty of
'MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
'GNU General Public License for more details.

'You should have received a copy of the GNU General Public License
'along with this program.  If not, see <http://www.gnu.org/licenses/>.


'/s       Run silently
'/e       Create Spreadsheet in Excel. Default is CSV output
'/g       Perform queries against CSV output from Sysinternals SigCheck and Carbon Black hash dump script.
'/a       Perform queries against EnCase tab separated value output or NetAMP CSV (Item Path, Logical Size, MD5, File Name, SHA256, Size (KB))
'/dcb     Disable Carbon Black
'/dms     Disable MalShare
'/dtc     Disable Threat Crowd lookups
'/det     Disable Proofpoint Emerging Threats Intelligence
'/dtg     Disable ThreatGRID
'filepath If you provide a file path that file will be used as sigcheck input. Also "starting lookups" prompt will be bypassed 

'For importing IP/domain CSV output into SQL you need to set the Spamhaus ZEN RBL, reverse DNS, Hosted Domains, WHOIS, Detection Name[#], URL Watch List columns to text stream [DT_TEXT]


'Data utilized from the following projects/locations:
'https://raw.githubusercontent.com/malicialab/avclass/master/data/default.aliases
'https://github.com/malicialab/avclass/blob/master/data/default.generics
'https://db-ip.com/db/lite.php - IP Geolocation by DB-IP
'https://tranco-list.eu/
'http://data.iana.org/TLD/tlds-alpha-by-domain.txt
'http://mirror2.malwaredomains.com/files/dynamic_dns.txt
'(others noted in code)



Const ForReading = 1, ForWriting = 2, ForAppending = 8
Const TristateTrue = -1
Const TristateFalse = 0
Const adChar = 129
Const adCmdStoredProc = 4
Const adParamInput = 1
Dim BoolEchoLog
Dim strresponseText
Dim strTmpURLs
Dim strScanDataInfo
Dim strVT_APIurl
Dim inLoopCounter
Dim strOptionalParameter
Dim strDataType
Dim strFullAPIURL
Dim strTmpVendorDetectionName
Dim StrTmpVendorDetectionURL
Dim DicScannedItems: Set DicScannedItems = CreateObject("Scripting.Dictionary")
Dim DicPendingItems: Set DicPendingItems = CreateObject("Scripting.Dictionary")
Dim boolPendingItems
Dim intCountPendItems
Dim strDebugPath
Dim strIPreportsPath
Dim strDomainreportsPath
Dim strURLreportsPath
Dim strHashReportsPath
Dim strAlienVaultreportsPath
DIm boolRescan
Dim BoolMetascan
Dim strAPIKey
Dim strMetaAPIkey
Dim strTempAPIKey
Dim strAPIproduct
Dim BoolDebugTrace
Dim intCountVendors
Dim intCountArrayIP
Dim strScannedItems
Dim strThisScanResults
Dim StrWebScanResults
Dim strDomainFromURL
Dim strTIScanResults
Dim strIPlinks
Dim strDomainLinks
Dim strMetaReportsPath
Dim strTempEncryptedAPIKey
Dim StrProcessedMetaScanIPreturn
Dim strThreatGRID_Output
Dim strTmpReturnedMetaScanIPData
Dim arrayTmpMetaScanIPResults
Dim StrIPMetaScanFormatted
Dim StrRBL_Results
DIm strMetaScanOnlineAssessments
Dim strMetaScanOnlineGeoIP
DIm strRandom
Dim BoolRunSilent
Dim boolsubmitVT
Dim dictNoSubmit: Set dictNoSubmit = CreateObject("Scripting.Dictionary")'stuff not to submit to VT if not already there
Dim dictNoDomainSubmit: set dictNoDomainSubmit = CreateObject("Scripting.Dictionary")'stuff not to submit to VT if not already there
Dim dictIPreported: set dictIPreported = CreateObject("Scripting.Dictionary")'IP addresses reported on already
Dim dictTLD: set dictTLD = CreateObject("Scripting.Dictionary")'Top Level Domains for Whois parent domain identification
Dim BoolReportWebScan
Dim BoolUseThreatGRID
Dim BoolUseThreatGRID_IP'Manual setting
DIm BoolUseCIF
Dim strTGAPIkey
Dim strCIF_APIkey
Dim StrTmpRBLOutput
Dim strCIFoutput
Dim intTGpageLimit
Dim BoolDNS_BLchecks
Dim intTabCounter
Dim intWriteRowCounter
Dim strTmpSSline 'temporary spreadsheet line
Dim strTmpVTTIlineE 'temporary line item for spreadsheet
Dim strTmpCBLlineE 'temporary line item for spreadsheet
Dim strTmpCudalineE 'temporary line item for spreadsheet
Dim strTmpZENlineE 'temporary line item for spreadsheet
Dim strDomainListOut 'temporary line item for spreadsheet
Dim strDFSlineE 'temporary line item for spreadsheet
Dim strTmpURIBLlineE
Dim enableSURBL
Dim strTmpSURbLineE
Dim strTmpZDBLlineE
Dim strTmpTGlineE
Dim strTmpCIFlineE
Dim strTmpMSOlineE
Dim strTmpCNlineE: strTmpCNlineE = "|"
Dim strTmpCClineE: strTmpCClineE = "|"
Dim strTmpRNlineE
Dim strTmpRClineE
Dim strTmpCITlineE
Dim strTmpWCO_CClineE
Dim strTmpIPContactLineE
Dim strTmpVTPositvLineE 'greatest value for positive detections
Dim strTmpIPlineE
Dim strTmpCacheLineE 'Was a cached lookup CacheLookup
Dim strTmpMalShareLineE
Dim strTmpPulsediveLineE
Dim BoolNoScanning
Dim strRevDNS
Dim BoolDisableVTlookup
Dim BooWhoIsIPLookup
Dim BoolNSRLLookup
Dim Dictripe: Set Dictripe = CreateObject("Scripting.Dictionary")
Dim DicDomainIPmatch: Set DicDomainIPmatch = CreateObject("Scripting.Dictionary")
Dim DictArin: Set DictArin = CreateObject("Scripting.Dictionary")
Dim DictAPNIC: Set DictAPNIC = CreateObject("Scripting.Dictionary")
Dim DictLACNIC: Set DictLACNIC = CreateObject("Scripting.Dictionary")
Dim DictAFRINIC: Set DictAFRINIC = CreateObject("Scripting.Dictionary")
Dim DictDDNS: Set DictDDNS = CreateObject("Scripting.Dictionary")
Dim DictCC: Set DictCC = CreateObject("Scripting.Dictionary")
Dim DictRevCC: Set DictRevCC = CreateObject("Scripting.Dictionary")
Dim strDDNS_Output
Dim strDDNSLineE
Dim BoolDDNS_Checks
Dim boolUseThreatCrowd
Dim boolUseAlienVault
Dim BoolUseETIntelligence: BoolUseETIntelligence = False 'automatically set to true if API key is loaded
DIm strTCrowd_Output 'Threat Crowd
Dim strTMPTCrowdLine 'Threat Crowd
Dim strPPoint_Output
Dim intVTListDataType' 0=unknown, 1 domain/IP, 2=hash, 3=hash/domain/ip
Dim intHashDetectionsLineE 'VirusTotal hash positive detections
Dim DictMicrosoftEncyclopedia: Set DictMicrosoftEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictTrendMicroEncyclopedia: Set DictTrendMicroEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictMcAfeeEncyclopedia: Set DictMcAfeeEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictSophosEncyclopedia: Set DictSophosEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictSymantecEncyclopedia: Set DictSymantecEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictESETEncyclopedia: Set DictESETEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictAviraEncyclopedia: Set DictAviraEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictDrWebEncyclopedia: Set DictDrWebEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictFSecureEncyclopedia: Set DictFSecureEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictPandaEncyclopedia: Set DictPandaEncyclopedia = CreateObject("Scripting.Dictionary")
Dim DictBitdefenderEncyclopedia: Set DictBitdefenderEncyclopedia = CreateObject("Scripting.Dictionary")
DIm dictEncyclopediaNegative: Set dictEncyclopediaNegative = CreateObject("Scripting.Dictionary")
Dim dictCountDomains: Set dictCountDomains = CreateObject("Scripting.Dictionary")
Dim intTmpMalScore
Dim IntTmpPUA_Score
Dim IntTmpGenericScore
Dim IntTmpAdjustedMalScore
Dim strTrendMicroLineE
Dim strMicrosoftLineE
Dim strMcAfeeLineE
Dim strSophoslineE
Dim strSymanteclineE
Dim strESETlineE
Dim strAviralineE
Dim strDrWeblineE
Dim boolCheckFSecure 
Dim boolCheckPanda
Dim strPandaLineE
Dim strFSecurelineE
Dim strBitdefenderlineE
DIm BoolCreateSpreadsheet
Dim strDateTimeLineE
Dim strDetectNameLineE
Dim strPassiveTotal 'spreadsheet output
Dim DictPUANames: Set DictPUANames = CreateObject("Scripting.Dictionary")
Dim DicTmpDnames: Set DicTmpDnames = CreateObject("Scripting.Dictionary")
Dim DictHktlNames: Set DictHktlNames = CreateObject("Scripting.Dictionary")
Dim DictTypeNames: Set DictTypeNames = CreateObject("Scripting.Dictionary")
Dim DictDSigNames: Set DictDSigNames = CreateObject("Scripting.Dictionary")
Dim DictMalDSigNames: Set DictMalDSigNames = CreateObject("Scripting.Dictionary")
Dim DictPUADSigNames: Set DictPUADSigNames = CreateObject("Scripting.Dictionary")
Dim DictGrayDSigNames: Set DictGrayDSigNames = CreateObject("Scripting.Dictionary")
Dim DictWhiteDSigNames: Set DictWhiteDSigNames = CreateObject("Scripting.Dictionary")
Dim DictPathVendorStat: Set DictPathVendorStat = CreateObject("Scripting.Dictionary")
Dim DictMalHash: set DictMalHash = CreateObject("Scripting.Dictionary")
Dim DictWhiteHash: set DictWhiteHash = CreateObject("Scripting.Dictionary")
Dim DictOrgWhois: Set DictOrgWhois = CreateObject("Scripting.Dictionary")
Dim DictWhois: Set DictWhois = CreateObject("Scripting.Dictionary")
Dim DictAlpabet: Set DictAlpabet = CreateObject("Scripting.Dictionary")
Dim IntTmpHkTlScore
Dim StrDetectionTypeLineE
Dim strTmpDomainRestric 'spreadsheet output for domain restricted
Dim strTmpSinkHole 'domain has been sinkholed
Dim BoolWhoisDebug: BoolWhoisDebug = False 'value is loaded from ini
Dim BoolForceWhoisLocationLookup 'VirusTotal doesn't always list location data such as the country code in their whois data.
Dim BoolDisableCacheLookup
Dim BoolDisableCaching
Dim intCIFlog
Dim BoolUseExcel
Dim strSSfilePath
Dim intVTErrorCount: intVTErrorCount = 0
Dim BoolUseCarbonBlack: BoolUseCarbonBlack = False
Dim BoolLimitCBQueries 'if a custom CSV export was feed to the script don't lookup API for known CSV items and rely on CSV data
Dim BoolEnableCarbonBlack
Dim StrBaseCBURL
Dim strCBfilePath 'CB File Path
Dim strCBdigSig 'CB Digital Sig
Dim strCBcompanyName 'CB Company Name
Dim strCBproductName 'Product Name
Dim strCBprevalence: strCBprevalence = 0 'Carbon Black Host Count
Dim strCBFileSize ' Carbon Black file size
DIm strCarBlackAPIKey
Dim BoolEnableThreatGRID
Dim BoolEnableCIF
dim BoolEnableMetascan
Dim boolEnableMalShare
Dim BoolDisableCBCachLookup
Dim intPublisherLoc: intPublisherLoc = -1
Dim intCompanyLoc: intCompanyLoc = -1
Dim intMD5Loc
Dim intHostLocation
Dim inthfPathLoc 
Dim dateTimeLoc: dateTimeLoc  = -1
Dim inthfProductLoc: inthfProductLoc = -1
Dim inthfSizeLoc: inthfSizeLoc = -1
Dim inthfPrevalenceLoc: inthfPrevalenceLoc = -1
Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")
Dim BoolHeaderLocSet: BoolHeaderLocSet = False
Dim intCSVRowLocation
Dim dicMD5Loc: Set dicMD5Loc = CreateObject("Scripting.Dictionary")'md5 Hash location
Dim ArraySigCheckData()
Dim BoolSigCheckLookup
Dim BoolEnCaseLookup: BoolEnCaseLookup = False
Dim BoolRecordVendorPathStats 'Record vendor match to path statistics
Dim int_CBFP_Location
Dim intCBDS_Location
Dim intCBCN_Location
Dim strStatsOutput
Dim BoolAddStats 'Add Digital Signature Prevalence	and Path Vendor Prevalence to CSV/spreadsheet output.
Dim boolSHA256csvLookup 'perform lookups against CSV input for SHA256 hashes. Required for NetAMP
Dim intVTpositiveDetections 'Number of VirusTotal positive detections
Dim boolEchoError
Dim boolNetAMPCSV 'Is a CSV export from NetAMP being used
Dim boolEnableCuckoo
Dim strCuckooScore
Dim strCuckooIPAddress
Dim strSigCheckFilePath
Dim strQueueParameters
Dim strDateLookupTrack 'track how long processing takes and subtract that time from the sleep lookup regulator
Dim boolSQLcache
DIm intRealMD5Loc
Dim intSHA256Loc
Dim intSHA1Loc
Dim intIMPLoc
Dim strFileMD5
Dim strFileSHA256
Dim strFileSHA1
Dim strFileIMP
Dim strCachePath
Dim strTLDPath
Dim strTmpPPointLine
Dim strETIntelligenceAPIKey
Dim strSQL_Intelligence_Output
Dim boolUseMySQL
Dim boolMySQLcache
Dim oCNCT_MySQL
Dim boolOutputHosts
Dim boolEnablePassiveTotal
Dim strPTAPIuser 'user name for PassiveTotal API
Dim strPTAPIkey 'PassiveTotal API key
Dim BoolUsePassiveTotal
Dim strPTdateTrack 'Date of last 15 PassiveTotal lookups
Dim strCategoryLineE
dim strWAPIkey
Dim boolEnableWhoAPI
Dim strWAPIdateTrack 'time tracking to comply with the WhoAPI one lookup a minute API limit
Dim BoolDebugDomainSQL: BoolDebugDomainSQL = False
Dim intWhoAPILimit
Dim strPE_TimeStamp
Dim StrYARALineE
Dim strFileTypeLineE
Dim strMimeTypeLineE
Dim intTGerrorCount
Dim boolTGwasEnabled
Dim intDelayBetweenLookups
Dim intPTlookupCount: intPTlookupCount = 0 ' count of PassiveTotal lookups
Dim intPTDailyLimit
Dim boolCheckDrWeb
Dim boolCheckAvira
Dim boolCheckSymantec
Dim strPPidsLineE
Dim DetectionNameSSlineE
Const dictKey  = 1
Const dictItem = 2
Dim intDetectionNameCount
Dim intDetectionCategory
Dim intHashlookupCount'tracks number of hask lookups for detection name association with IP/domain
Dim intaddDNameCount 'amplification for number of columns for hash IP/domain association
Dim dictDnameWatchList: set dictDnameWatchList = CreateObject("Scripting.Dictionary")
Dim dictKWordWatchList: set dictKWordWatchList  = CreateObject("Scripting.Dictionary") 'key words used for AlienVault text search
Dim strDnameWatchLineE 
Dim intHashPositiveThreashold 'used to limit hash lookups for hash IP/domain association where there are less detections than this number
Dim dictURLWatchList: set dictURLWatchList = CreateObject("Scripting.Dictionary")
Dim strURLWatchLineE 
Dim BoolURLWatchLlistRegex
Dim dictIPdomainWatchList: set dictIPdomainWatchList = CreateObject("Scripting.Dictionary")
Dim strIpDwatchLineE
dim ArrayDnameLineE()'dim array used for storing detection names associated with domain/IP
Dim strWhoAPIRUL: strWhoAPIRUL = "http://api.whoapi.com/?"
Dim BoolEnableDomainAPI
Dim strDomainAPIURL: strDomainAPIURL = "http://api.freedomainapi.com/?"
Dim BoolEnableTIA
Dim strTIAkey
Dim boolCheckBitdefender
dim tmpArrayPointer()
Dim strtmpVendQueue 'contains the list of TIA items to look up
Dim boolEnableTIAqueue
DIm boolPendingTIAItems
Dim dictUrlOut: Set dictUrlOut = CreateObject("Scripting.Dictionary") 'used to track TIA lookups and output URLs to strThisScanResults
Dim BoolSkipedVTlookup 'If true a cached VT result was pulled
Dim sleepOnSkippedVT 'Set to true to sleep when a VT result was skipped
DIm boolCheckSophos
Dim boolCHeckMcAfee
Dim boolCheckMicrosoft
Dim BoolCheckTrendMicro
Dim boolCheckESET
Dim AlienVaultPulseLine
Dim AlienVaultValidation 
Dim boolCacheVTNoExist
Dim cudaDNS
Dim zenDNS
Dim uriblDNS
Dim surbl
Dim abuseatDNS
Dim boolDisableDomain_BLchecks
Dim boolDisableAlienVaultWhoIs
Dim useAlienVapiKey: useAlienVapiKey = True
Dim strAlienVaultkey
DIm enableZEN
Dim enableSORBS 
Dim strSORBSlineE
Dim enableURIBL
Dim EnableCBL
Dim boolEnableZDBL
Dim EnableBarracuda
Dim CIFurl
Dim boolAlienVaultPassiveDNS
Dim strQuad9DNS
Dim boolUseQuad9
Dim boolAlienVaultNIDS
Dim AlienNIDS
Dim AlienNIDScount
Dim AlienNIDSCat
Dim dictNIDScategory: set dictNIDScategory = CreateObject("Scripting.Dictionary")
Dim dictNIDSsigName: set dictNIDSsigName = CreateObject("Scripting.Dictionary")
Dim dictNIDStmpCategory: set dictNIDStmpCategory = CreateObject("Scripting.Dictionary")
Dim dictGenericLabel: set dictGenericLabel = CreateObject("Scripting.Dictionary")
Dim dictTrancoList: set dictTrancoList =  CreateObject("Scripting.Dictionary")
Dim boolUseTrancoList
Dim boolSkipOnTrancoHit
Dim boolSkipDomain: boolSkipDomain = False 'skip lookups when domain matched Tranco list
Dim boolSigCheckDebug: boolSigCheckDebug = false 
Dim SorbsDNS
Dim enableFreeGeoIP
Dim boolIniNotify: boolIniNotify = True 'Only notify once of ini not existing
Dim strTmpKeyWordWatchList 'Watch list for AlienVault keyword search
Dim strCIFconfidence
Dim boolAlienHostCheck
Dim DisplayVendor 'Vendor name to output all detection names for 
Dim strDiplayVendDname 'Output string for Diplay vendor detection name
Dim dictFamilyNames: set dictFamilyNames = CreateObject("Scripting.Dictionary") 'Tracking of known family names
Dim intClippingLevel 'clipping level score for detection name output in IP/Domain mode
Dim BoolCacheRelatedHashLookups 'domain and IP address associated hashes
Dim boolDisableSQL_IQ: boolDisableSQL_IQ = True 'Unimplemented feature SQL_Intelligence_Query
Dim boolUseRIPE
dim boolUseARIN
Dim SignatureDateCheck
Dim intSigDateRange
Dim strCAPEport
Dim UniqueString
Dim boolLogURLs 'Output URLs associated with the lookup items.
Dim boolLogIPs 'Output IP addresses associated with the lookup items.
Dim boolEnableCuckooV2 'Perform API queries for hashes against Cuckoo v2
Dim strCuckooV2IPAddress 'Cuckoo v2 host or IP address
Dim strCuckooPort 'Cuckoo v2 port
Dim boolLogHashes 'Output hashes associated with the lookup items.
Dim enableIP_DB 'Use internal IP-DB for GeoIP
Dim strReportsPath
Dim boolTrancoSQL: boolTrancoSQL = True
Dim sysinternalsWhois 'Use command line sysinternals whois tool for whois lookups
Dim boolWhoisCache 'Cache whois results 
Dim boolVTuseV3 'Use v3 of VirusTotal API
Dim boolVT_V3 'internal setting used to track VT JSON version
Dim etHashLookedUp 'have we looked up hash on Proofpoint ET 
Dim tcHashLookedUp 'have we looked up hash on ThreatCrowd
Dim boolCacheDomain 'Database caching for domain lookups
Dim DicIP_Context: Set DicIP_Context = CreateObject("Scripting.Dictionary") 'Seclytics IP Address context
Dim DicFile_Context: Set DicFile_Context = CreateObject("Scripting.Dictionary") 'Seclytics File context
Dim boolPulsedive
Dim PulsediveAPIprompt
Dim BoolSeclytics 'set to true to use Seclytics
Dim sslOrg 'Pulsedive
dim sslSubject 'Pulsedive
'LevelUp
Dim dictAllTLD: set dictAllTLD = CreateObject("Scripting.Dictionary")
Dim dictSLD: set dictSLD = CreateObject("Scripting.Dictionary")
Dim dictPrev: set DictPrev = CreateObject("scripting.Dictionary")
Dim SecondLevelDict: Set SecondLevelDict = CreateObject("Scripting.Dictionary")
Dim ThirdLevelDict: Set ThirdLevelDict = CreateObject("Scripting.Dictionary")
Dim inputFile
Dim boolNext
Dim boolInvalid
'end LevelUp


'--- Config items
BoolReportOnly = False 'Dont submit to VirusTotal
BoolNoScanning = True 'Don't scan anything with VirusTotal. Scanning something provides the scanned item publicly. Default is True preventing scanning.
BoolDisableVTlookup = False 'Don't perform Virus Total lookups. Default is False. Setting to True breaks some functionality
sleepOnSkippedVT = True 'Default value is True. Set to False if only VirusTotal API is being used. Set to true to sleep when a VirusTotal result was pulled from cache. Setting True prevents overwhelming other APIs.
intDelayBetweenLookups = 15052 'miliseconds to wait between each lookup (default 15052 one lookup every 15 seconds), 4052 AlienVault with API Key
boolCacheVTNoExist = False 'Cache VirusTotal has does not exist results. Default value is False
BoolDisableCacheLookup = False 'Do not query cache for lookups
BoolDisableCaching = False ' Do not write cache items
boolCacheDomain = false 'Cache domain lookups
intHashCacheThreashold = 900 'number of days to use a cached return before refreshing. Anything older than this will not be refreshed. Default set to same as intCacheRefreshLimit
intCacheRefreshLimit = 900 'number of days back that a refresh is allowed. Anything older than this will not be refreshed.
intRefreshAge = -1 'Number of days from fist time seeing the hash that you want to refresh the cache data (get updated results) for processed items. Default value is 10
BoolRecordVendorPathStats = True 'Record vendor match to path statistics. Set to False to prevent recording unwanted statistics 
BoolAddStats = True 'Adds statistics for processed hashes. Default value is True
BoolCreateSpreadsheet = True 'creates CSV output. Default is True
BoolUseExcel = False 'Default value is false to disable the use of Excel. 
BoolAddStats = True 'Add Digital Signature Prevalence and Path Vendor Prevalence to CSV/spreadsheet output. Must have recorded data \cache\digsig.dat and \cache\pathvend.dat
BoolUseSQLite = True 'Store data in SQLite vs the file system.
boolUseMySQL = False 'This was a test feature. Do not enable
strDatabasePath = "vttl.db" 'Default is vttl.db which will exist in current directory.
boolOutputHosts = False 'Set to True to have the script import/export Carbon Black host names associated with a hash
boolNoCrLf = True 'Remove carriage return and line feed from cell entries.
boolLogURLs = True 'Log URLs associated with an IP/Domain
boolLogHashes = True 'Output URLs and hashes associated with the lookup items. (outputs from VirusTotal and Seclytics)
boolLogIPs = True 'Output IP addresses associated with the lookup items.
'--- Intenal checks
BoolURLWatchLlistRegex = True 'set to true to enable regex for URL watch list. False will match the string
BoolDDNS_Checks = True 'Dynamic DNS check
boolUseTrancoList = True 'Check domains against https://tranco-list.eu
boolSkipOnTrancoHit = True 'Skip VirusTotal lookups when domain match against https://tranco-list.eu
sysinternalsWhois = False 'Use command line sysinternals whois tool for whois lookups
boolWhoisCache = False 'Cache whois results 
'--- VirusTotal custom checks
intDetectionNameCount = 1 'Set greater than zero to enable reporting on detection names associated with domain/IP. set to zero to disable.
intDetectionCategory = 2 'associated with domain/IP category to use: detected_downloaded_samples=0, detected_referrer_samples=1, detected_communicating_samples=2
intHashPositiveThreashold = 9 'Positive detection threshold to perform hash lookups for IP/domain association. Will only report on detections above the threshold.
boolVTuseV3 = True
'--- DNS vendor checks
enableZEN = True
enableURIBL = True
EnableCBL = True
boolEnableZDBL = True 
EnableBarracuda = True
enableSURBL = True
enableSORBS = True 
boolUseQuad9 = True
BoolDNS_BLchecks = True 'Perform DNS block list checks
boolDisableDomain_BLchecks = False 'Disables uribl and surbl. Default value is True
cudaDNS = ""
zenDNS = ""
uriblDNS = ""
surblDNS =  ""
abuseatDNS = ""
'--- API vendor lookup config section
boolUseRIPE = True ' Réseaux IP Européens (RIPE NCC) API
boolUseARIN = True 'American Registry for Internet Numbers (ARIN) API
boolEnableCuckoo = False 'Perform API queries for hashes against CAPE
strCuckooIPAddress = "" 'CAPE host or IP address
strCAPEport = "" 'CAPE port
boolEnableCuckooV2 = False'Perform API queries for hashes against Cuckoo v2
strCuckooV2IPAddress = "" 'Cuckoo v2 host or IP address
strCuckooPort = "" 'Cuckoo v2 port
BoolUseThreatGRID_IP = False 'Perform ThreatGRID IP address lookup
intTGpageLimit = 10 'Default seemed to be giving 10,000 pages of data / hundreds of MB of data so restrict this with a low number
boolUseThreatCrowd = True 'Threat Crowd threshold is six lookups a minute. 
boolUseAlienVault = True 'AlienVault lookups
boolDisableAlienVaultWhoIs = False 'Disable whois lookups with AlienVault OTX. Default is False.
boolAlienVaultPassiveDNS = True 'Use AlienVault passive DNS lookup API. Default is True
boolAlienVaultNIDS = True ' Use AlienVault NIDS API. Requires API Key
boolAlienHostCheck = True ' Use AlienVault to get host names
boolEnableETIntelligence = False 'Emerging threats from Proofpoint
BoolForceWhoisLocationLookup = True 'disable this if domain whois location information is not required. Domain location information is populated by whois and IP address location data is populated by GeoIP.
intCIFlog = "1"  'set to 1 to disable CIF logging the query. Set to 0 to enable CIF logging the query.
strCIFconfidence = "0" 'lowest CIF rated confidence to return. 
strCIFurl = "" ' URL to use for CIF requests (supports v2 currently) example: https://domain.com/indicators
BoolEnableCIF = True 'Perform queries against CIF. Disabled if no API key provided
BoolEnableCarbonBlack = True 'Perform queries for md5 against Carbon Black. Disabled if no API key and URL provided
BoolDisableCBCachLookup = True 'Default value is True. Prevents getting CB results from cache
BoolLimitCBQueries = True 'Default is True. If a custom CSV export was feed to the script; rely on CSV data and don't lookup API for known CSV items. Set to False to perform queries against CB regardless of CSV data.
BoolEnableThreatGRID = True 'Perform queries against ThreatGRID. Disabled if no API key provided
BoolEnableMetascan = False 'Disabled due to API changes. Disabled if no API key provided 
boolEnableMalShare = True 'Perform queries against malshare.com. Disabled if no API key provided
boolEnablePassiveTotal = True 'Perform queries for publisher on PassiveTotal. 
intPTDailyLimit = 100 'Number of PassiveTotal queries allowed in a day. Default is 100.
enableFreeGeoIP = False 'Run SubmitGIP
enableIP_DB = True 'Use internal IP-DB for GeoIP
boolEnableWhoAPI = False 'Enable WhoAPI whois lookups
BoolEnableDomainAPI = True 'Enable freedomainapi.com
intWhoAPILimit = 60 'Number of seconds to wait between lookups. Set to 60 for one lookup a minute. 30 for two lookups a minute.
boolCheckProofpointIDS = False 'Check for ET IDS signatures related to the lookups
BoolEnableTIA = True 'Use Threat Intelligence Aggregator
boolEnableTIAqueue = False 'Queue output rows where TIA lookups did not have results available yet. Enabling ensures all detection name results are given from TIA. One side effect is row output may not be in the same order as the provided hash list. May have issues if missing required .net component.
SignatureDateCheck = True 'Alert if any dates from TIA for signature are within intSigDateRange
intSigDateRange = 3 'Date range in days to alert on signature dates from TIA
boolCheckFSecure = True 'Lookup F-Secure write-ups via Threat Intelligence Aggregator
boolCheckBitdefender = True 'Lookup Bitdefender write-ups via Threat Intelligence Aggregator
boolCheckPanda = True 'Lookup Panda write-ups via Threat Intelligence Aggregator
boolCheckSophos = True 'Lookup write-ups via Threat Intelligence Aggregator
boolCHeckMcAfee = True 'Lookup write-ups via Threat Intelligence Aggregator
boolCheckMicrosoft = True 'Lookup write-ups via Threat Intelligence Aggregator
BoolCheckTrendMicro = True 'Lookup write-ups via Threat Intelligence Aggregator
boolCheckDrWeb = True 'Check for Dr Web write-up (requires TIA API)
boolCheckAvira = True 'Check for Avira write-up (requires TIA API)
boolCheckSymantec = True 'Check for Symantec write-up (requires TIA API)
boolCheckESET = True 'Lookup write-ups via Threat Intelligence Aggregator
BoolNSRLLookup = False 'Public service is for demo purposes only. Need to stand up your own server and modify to query it.
BoolSeclytics = False 'set to true to use Seclytics
boolPulsedive = False 'Set to true to use Pulsedive
PulsediveAPIprompt = True 'Prompt for Pulsedive API key
SeclytRepReason = "" 'Seclytics Reputation and Reason
SeclytFileRep = "" 'Seclytics Associated File Metadata
SeclytFileCount = "" 'Seclytics File Count"
DisplayVendor = "" 'Add column to display all of this vendor's detection names. Example: BitDefender
intClippingLevel = 2 'Domain/IP reporting for detection name will report on name label with score greater than this
BoolCacheRelatedHashLookups = True
'--- End config items

'----------------reconfigure
intDelayBetweenLookups = ValueFromINI("vttl.ini", "main", "time_between_lookups", intDelayBetweenLookups) 'load value from INI
if isnumeric(intDelayBetweenLookups) = False then 'check value from INI
	msgbox "intDelayBetweenLookups must be a numeric value:" & intDelayBetweenLookups
	wscript.quit (22)
end if
if intDelayBetweenLookups < 10000 then 
	boolUseThreatCrowd = False 'disable when beyond vendor provided threshold
	boolEnableMalShare = False 'only provides threshold for downloads but disabling to be safe
end if

BoolDisableCaching = ValueFromINI("vttl.ini", "main", "disable_CacheWrite", BoolDisableCaching) ' Do not write cache items
BoolDisableCacheLookup = ValueFromINI("vttl.ini", "main", "disable_CacheRead", BoolDisableCacheLookup) 'Do not query cache for lookups
boolWhoisCache = ValueFromINI("vttl.ini", "main", "whoisCache", boolWhoisCache) 'Cache whois data for domains
boolCacheDomain = ValueFromINI("vttl.ini", "main", "DomainCache", boolWhoisCache) 'Cache domain lookups
BoolUseExcel = ValueFromINI("vttl.ini", "main", "enable_Excel", BoolUseExcel) 'load value from INI
sleepOnSkippedVT = ValueFromINI("vttl.ini", "main", "SleepOnCachedLookup", sleepOnSkippedVT) 'load value from INI to sleep if VirusTotal results came from cache
intRefreshAge = ValueFromINI("vttl.ini", "main", "HashRefresh", intRefreshAge) 'Number of days from first time seeing the hash that you want to refresh the cache data (get updated results) for processed items. Default value is 10
strDatabasePath = ValueFromINI("vttl.ini", "main", "database_location", strDatabasePath)
BoolDisableVTlookup = ValueFromINI("vttl.ini", "vendor", "disable_VirusTotal", BoolDisableVTlookup) 'load value from INI
boolUseAlienVault = ValueFromINI("vttl.ini", "vendor", "enable_AlienVault", boolUseAlienVault) 'load value from INI
boolDisableAlienVaultWhoIs = ValueFromINI("vttl.ini", "vendor_AlienVault", "disable_whois", boolDisableAlienVaultWhoIs) 'Disable whois lookups with AlienVault OTX. Default is False.
boolAlienVaultPassiveDNS = ValueFromINI("vttl.ini", "vendor_AlienVault", "enable_passiveDNS", boolAlienVaultPassiveDNS) 'Use AlienVault passive DNS lookup API. Default is True. populates hosted domain column
boolAlienVaultNIDS = ValueFromINI("vttl.ini", "vendor_AlienVault", "enable_NIDS", boolAlienVaultNIDS) ' Use AlienVault NIDS API. Requires API Key
useAlienVapiKey = ValueFromINI("vttl.ini", "vendor_AlienVault", "use_AlienVaultAPIkey", useAlienVapiKey) ' Prompt for and use AlienVault API Key
boolAlienHostCheck  = ValueFromINI("vttl.ini", "vendor_AlienVault", "enable_HostDetection", boolAlienHostCheck) ' Use AlienVault to populate hosted domain column (has hosts passive DNS does not)
BoolEnableTIA = ValueFromINI("vttl.ini", "vendor", "enable_TIA", BoolEnableTIA)  'Use Threat Intelligence Aggregator (TIA)
SignatureDateCheck = ValueFromINI("vttl.ini", "vendor", "TIA_DateCheck", SignatureDateCheck)'Alert if any dates from TIA for signature are within intSigDateRange
intSigDateRange  = ValueFromINI("vttl.ini", "vendor", "TIA_DateRange", intSigDateRange) 'Date range in days to alert on signature dates from TIA
BoolEnableCarbonBlack = ValueFromINI("vttl.ini", "vendor", "enable_CarbonBlack", BoolEnableCarbonBlack)
BoolEnableThreatGRID = ValueFromINI("vttl.ini", "vendor", "enable_ThreatGRID", BoolEnableThreatGRID)
enableZEN = ValueFromINI("vttl.ini", "vendor", "enable_ZEN", enableZEN)
enableURIBL = ValueFromINI("vttl.ini", "vendor", "enable_URIBL", enableURIBL)
boolEnableZDBL = ValueFromINI("vttl.ini", "vendor", "enable_ZDBL", boolEnableZDBL) 
EnableBarracuda = ValueFromINI("vttl.ini", "vendor", "enable_Barracuda", EnableBarracuda)
enableSURBL = ValueFromINI("vttl.ini", "vendor", "enable_SURBL", enableSURBL)
enableSORBS = ValueFromINI("vttl.ini", "vendor", "enable_SORBS", enableSORBS) 
boolUseQuad9 = ValueFromINI("vttl.ini", "vendor", "enable_Quad9", boolUseQuad9)
boolEnableMalShare = ValueFromINI("vttl.ini", "vendor", "enable_MalShare", boolEnableMalShare)
boolEnableWhoAPI = ValueFromINI("vttl.ini", "vendor", "EnableWhoAPI", boolEnableWhoAPI)
BoolEnableDomainAPI = ValueFromINI("vttl.ini", "vendor", "EnableDomainAPI", BoolEnableDomainAPI)
boolEnablePassiveTotal = ValueFromINI("vttl.ini", "vendor", "EnablePassiveTotal", boolEnablePassiveTotal)
boolEnableETIntelligence = ValueFromINI("vttl.ini", "vendor", "UseETIntelligence", boolEnableETIntelligence)
BoolUseCIF = ValueFromINI("vttl.ini", "vendor", "UseCIF", BoolUseCIF)
sysinternalsWhois = ValueFromINI("vttl.ini", "vendor", "SysinternalsWhois", sysinternalsWhois)
BoolDNS_BLchecks = ValueFromINI("vttl.ini", "vendor", "enable_BlockLists", BoolDNS_BLchecks) 'Perform DNS block list checks
boolDisableDomain_BLchecks = ValueFromINI("vttl.ini", "vendor", "disable_DomainBlockLists", boolDisableDomain_BLchecks) 'Disables uribl and surbl. Default value is True
cudaDNS = ValueFromINI("vttl.ini", "DNS_Server", "Barracuda", cudaDNS)
zenDNS = ValueFromINI("vttl.ini", "DNS_Server", "zen", zenDNS)
uriblDNS = ValueFromINI("vttl.ini", "DNS_Server", "uribl", uriblDNS)
surblDNS =  ValueFromINI("vttl.ini", "DNS_Server", "surbl", surblDNS)
abuseatDNS = ValueFromINI("vttl.ini", "DNS_Server", "abuseat", abuseatDNS)'cbl.abuseat.org
SorbsDNS = ValueFromINI("vttl.ini", "DNS_Server", "SORBS", "")
EnableCBL = ValueFromINI("vttl.ini", "vendor", "enable_CBL", EnableCBL)
BoolEnableCIF = ValueFromINI("vttl.ini", "vendor", "enable_CIF", BoolEnableCIF)
strCIFurl = ValueFromINI("vttl.ini", "vendor", "CIF_URL", strCIFurl)
boolEnableCuckoo = ValueFromINI("vttl.ini", "vendor", "enable_CAPE", boolEnableCuckoo)
strCuckooIPAddress = ValueFromINI("vttl.ini", "vendor", "CAPE_Address", strCuckooIPAddress)
strCAPEport = ValueFromINI("vttl.ini", "vendor", "CAPE_Port", strCAPEport)
boolEnableCuckooV2 = ValueFromINI("vttl.ini", "vendor", "enable_Cuckoo", boolEnableCuckooV2)
strCuckooV2IPAddress = ValueFromINI("vttl.ini", "vendor", "Cuckoo_Address", strCuckooV2IPAddress)
strCuckooPort = ValueFromINI("vttl.ini", "vendor", "Cuckoo_Port", strCuckooPort)
DisplayVendor = ValueFromINI("vttl.ini", "VirusTotal", "DisplayVendor", DisplayVendor) '
boolUseRIPE = ValueFromINI("vttl.ini", "vendor", "UseRIPE", boolUseRIPE)
boolUseARIN = ValueFromINI("vttl.ini", "vendor", "useARIN", boolUseARIN)
enableFreeGeoIP = ValueFromINI("vttl.ini", "vendor", "useFreeGeoIP", enableFreeGeoIP)
boolLogURLs = ValueFromINI("vttl.ini", "vendor", "LogURLs", boolLogURLs)
boolLogHashes = ValueFromINI("vttl.ini", "vendor", "LogHashes", boolLogHashes)
boolLogIPs = ValueFromINI("vttl.ini", "vendor", "LogIPs", boolLogIPs)
boolUseTrancoList = ValueFromINI("vttl.ini", "vendor", "TrancoList", boolUseTrancoList) 'Check domains against https://tranco-list.eu
boolSkipOnTrancoHit = ValueFromINI("vttl.ini", "vendor", "SkipLookupsOnTrancoMatch", boolSkipOnTrancoHit)
BoolSeclytics = ValueFromINI("vttl.ini", "vendor", "useSeclytics", BoolSeclytics)
boolPulsedive = ValueFromINI("vttl.ini", "vendor", "usePulsedive", boolPulsedive)
PulsediveAPIprompt = ValueFromINI("vttl.ini", "vendor", "PulsediveAPIprompt", PulsediveAPIprompt)
BoolURLWatchLlistRegex = ValueFromINI("vttl.ini", "VirusTotal", "UseRegexForURL", BoolURLWatchLlistRegex)
intDetectionNameCount = ValueFromINI("vttl.ini", "VirusTotal", "WebSamplesToCheck", intDetectionNameCount) 'Set greater than zero to enable reporting on detection names associated with domain/IP. set to zero to disable.
intDetectionCategory = ValueFromINI("vttl.ini", "VirusTotal", "WebSampleCategory", intDetectionCategory) 'associated with domain/IP category to use: detected_downloaded_samples=0, detected_referrer_samples=1, detected_communicating_samples=2
intHashPositiveThreashold = ValueFromINI("vttl.ini", "VirusTotal", "WebSamplePositiveThreshold", intHashPositiveThreashold) 'Positive detection threshold to perform hash lookups for IP/domain association. Will only report on detections above the threshold.
BoolDebugTrace = ValueFromINI("vttl.ini", "Debug", "trace", BoolDebugTrace)
boolSigCheckDebug = ValueFromINI("vttl.ini", "Debug", "sigcheck", boolSigCheckDebug)
BoolWhoisDebug = ValueFromINI("vttl.ini", "Debug", "Whois", BoolWhoisDebug)' used to do additional messaging and logging to troubleshoot whois and some geolocation
strDebugPath = ValueFromINI("vttl.ini", "Debug", "path", strDebugPath)
'----------------end reconfigure

If len(strCAPEport) > 0 then strCAPEport = ":" & strCAPEport
if strCuckooIPAddress = "" then boolEnableCuckoo = False
If len(strCuckooPort) > 0 then strCuckooPort = ":" & strCuckooPort
if strCuckooV2IPAddress = "" then boolEnableCuckooV2 = false


'set types
if isnumeric(intHashPositiveThreashold) then
	intHashPositiveThreashold = cint(intHashPositiveThreashold)
else
	msgbox "WebSamplePositiveThreshold (intHashPositiveThreashold) is not a numeric value. Script will use 9"
	intHashPositiveThreashold = 9
end if

if isnumeric(intDetectionCategory) then
	intDetectionCategory = cint(intDetectionCategory)
else
	msgbox "WebSampleCategory (intDetectionCategory) is not a numeric value. Script will use 2"
	intDetectionCategory = 2
end if

if isnumeric(intDetectionNameCount) then
	intDetectionNameCount = cint(intDetectionNameCount)
else
	msgbox "WebSamplesToCheck (intDetectionNameCount) is not a numeric value. Script will use 0 to disable lookups"
	intDetectionNameCount = 2
end if
'end set types


if isnumeric(intRefreshAge) then 'make sure we are looking back in time for refresh of hash intel
	if left(intRefreshAge, 1) <> "-" then
		intRefreshAge = cint("-" & intRefreshAge)
	end if
end if

boolPendingItems = False
BoolEchoLog = False
boolRescan = False
BoolUseThreatGRID = False
BoolUseCIF = False

BooWhoIsIPLookup = True

boolSHA256csvLookup = False
boolEchoError = True
boolNetAMPCSV = False

if BoolDNS_BLchecks = False then
	enableZEN = False
	enableURIBL = False
	EnableCBL = False
	boolEnableZDBL = False 
	EnableBarracuda = False
	enableSORBS = False
end if
if boolDisableDomain_BLchecks = True then
	enableURIBL = False
	boolEnableZDBL = False 
	enableSURBL = False
end if

if sleepOnSkippedVT = False then
	'disable anything that might get overwhelmed
  boolUseThreatCrowd = False
  boolEnableMalShare = False 'only provides threshold for downloads but disabling to be safe
end if

'this needs to be after the config section to overide the queue behavior if .net framework 3.5 is not installed
if boolEnableTIAqueue = True then
on error resume next
Dim outQueue: Set outQueue = CreateObject("System.Collections.Queue") 
Dim lookupQueue: Set lookupQueue = CreateObject("System.Collections.Queue") 
if error.number <> 0 then boolEnableTIAqueue = False
on error goto 0
end if

	strRandom = "4bv3nT9vrkJpj3QyueTvYFBMIvMOllyuKy3d401Fxaho6DQTbPafyVmfk8wj1bXF" 'encryption key. Change if you want but can only decrypt with same key
intTabCounter = 1
intWriteRowCounter = 1

'set path strings and create sub folders
CurrentDirectory = GetFilePath(wscript.ScriptFullName)
CreateFolder CurrentDirectory & "\Debug\"
if strDebugPath = "" then strDebugPath = CreateFolder(CurrentDirectory & "\Debug\Operations\")
strIPreportsPath = CreateFolder(CurrentDirectory & "\Debug\IP_Reports")
strDomainreportsPath = CreateFolder(CurrentDirectory & "\Debug\Domain_Reports")
strURLreportsPath = CreateFolder(CurrentDirectory & "\Debug\URL_Reports")
strHashReportsPath = CreateFolder(CurrentDirectory & "\Debug\Hash_Reports")
strMetaReportsPath = CreateFolder(CurrentDirectory & "\Debug\Meta_Reports")
strAlienVaultreportsPath = CreateFolder(CurrentDirectory & "\Debug\AlienVault")
strCachePath = CreateFolder(CurrentDirectory & "\cache")
strTLDPath = CreateFolder(CurrentDirectory & "\tld")
strReportsPath =  CreateFolder(CurrentDirectory & "\Reports")

strStatsOutput = strReportsPath & "\VTTL_WithStats_" & udate(now) & ".csv"
UniqueString = udate(now)
strSSfilePath = strReportsPath & "\VTTL_" & UniqueString & ".csv"

DIm objShellComplete
Set objShellComplete = WScript.CreateObject("WScript.Shell") 
Dim objFile

'debug logging
if objFSO.fileexists(strDebugPath & "\enable") then
  BoolDebugTrace = True

end if


' Store the arguments in a variable:
 Set objArgs = Wscript.Arguments

boolSQLcache = False
if BoolUseSQLite = True then
  
	if objFSO.fileexists(strDatabasePath) = false then 'use default database if none exists
		if objFSO.fileexists("default.db") = True then
			objFSO.CopyFile "default.db", strDatabasePath
		end if
	end if
  
  'SQL Connect
  Dim oCS     : oCS       = "Driver={SQLite3 ODBC Driver};Database=" & strDatabasePath & ";Version=3;"
  Dim oCNCT   : Set oCNCT = CreateObject( "ADODB.Connection" )

  redim preserve ArraySigCheckData(1)
  if SQLTestConnect = True then 
		boolSQLcache = True
	else
		BoolUseSQLite = False
	end if
end if

if BoolUseSQLite = False then 
	enableIP_DB = False 'Use internal IP-DB for GeoIP
	boolTrancoSQL =False
end if

if dictTrancoList.count = 0 and boolTrancoSQL = False then boolUseTrancoList = False

if boolUseMySQL = True then 'Experimental. Do not use
  'SQL Connect
  Dim oCS_MySQL     : oCS_MySQL = "Driver={MySQL ODBC 5.3 ANSI Driver};Server=;" & _
                     "Database=VTTL; User=; Password=;"
  Set oCNCT_MySQL = CreateObject( "ADODB.Connection" )
  Set cmdMySQL = createobject("ADODB.Command")
  boolMySQLcache = TableCheck
end if

if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "boolSQLcache=" & boolSQLcache ,BoolEchoLog
if WScript.Arguments.Count = 0 then
    BoolRunSilent = False
else
    ' all command-line arguments
     For Each strArg in objArgs
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "_Parameter" & ".txt", "strArg=" & strArg ,BoolEchoLog
       select case lcase(strArg)
          case "/s"  
            BoolRunSilent = True 
            boolEchoError = False
            AddQueueParameter("/s")
          case "/e"  
            BoolCreateSpreadsheet = True 
            BoolUseExcel = True
            AddQueueParameter("/e")
          case "/g" 
            BoolSigCheckLookup = True
            AddQueueParameter("/g")
         case "/a" 
            BoolEnCaseLookup = True
            AddQueueParameter("/a")
         case "/dcb" 
            BoolEnableCarbonBlack = false
            AddQueueParameter("/dcb")
         case "/dxf" 
            boolUseXforce = false
            AddQueueParameter("/dxf")

         case "/dms" 
          boolEnableMalShare = False
          AddQueueParameter("/dms")

         case "/dtc"
          boolUseThreatCrowd = False
          AddQueueParameter("/dtc")   
         case "/dav"
			boolUseAlienVault = False
			AddQueueParameter "/dav"
		 case "/det"
          boolEnableETIntelligence = False
          AddQueueParameter("/det")
          boolCheckProofpointIDS = False
		 Case "/dtg"
          BoolUseThreatGRID = False
          BoolUseThreatGRID_IP = False
          BoolEnableThreatGRID = False
          AddQueueParameter("/dtg")
         Case "/dtia"
			BoolEnableTIA = False
		 case else
          
          if strSigCheckFilePath = "" then
            if objFSO.fileexists(strArg) then
              strSigCheckFilePath = lcase(strArg)
            else
              msgbox "invalid argument: " & strArg
            end if
          else
            msgbox "invalid argument: " & strArg
          end if
      end select
     Next
     
end if
if BoolEnCaseLookup = True and BoolSigCheckLookup = True then
  StrQuestion = msgbox("The script can only import using certain formats such as EnCase/NetAMP (tab) or SigCheck/Autorunsc (CSV) data. Do you want to perform lookups against EnCase/NetAMP?",4,"VTTL Question")
  if StrQuestion = 7 then'no
    BoolEnCaseLookup = False
  elseif StrQuestion = 6 then'yes
    BoolSigCheckLookup = False
  else  
    msgbox "invalid response. Script will now exit"
    wscript.quit
  end if
end if
if BoolEnCaseLookup = True then 'EnCase export does not provide vendor name
  BoolRecordVendorPathStats = False
end if



if BoolDebugTrace = True and BoolRunSilent = False Then
  msgbox "debug logging is enabled!"
end if
if BoolNoScanning = False and BoolRunSilent = False Then
  msgbox "Scanning is enabled!"
end if
if BoolReportOnly = True and BoolRunSilent = False Then
  msgbox "Submitting is disabled!"
end if


'Check and save dynamic DNS dat
if objFSO.fileexists(CurrentDirectory &"\DDNS.dat") = false then
  Dload_DDNS "http://mirror2.malwaredomains.com/files/dynamic_dns.txt", "\DDNS.dat"
end if

'load dynamic DNS dat
if objFSO.fileexists(CurrentDirectory &"\DDNS.dat") then
  Set objFile = objFSO.OpenTextFile(CurrentDirectory &"\DDNS.dat")
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        if Left(strData, 1) <> "#" and instr(strData, vbtab) then
          strTmpArrayDDNS = split(strData, vbtab)
          if DictDDNS.exists(strTmpArrayDDNS(0)) = False then _
          DictDDNS.add strTmpArrayDDNS(0), 1
        end if
        on error goto 0
    end if
  loop
else
  BoolDDNS_Checks = False
end if


'Create country code dat if does not exist
if objFSO.fileexists(CurrentDirectory &"\cc.dat")  = False then 
	'WriteCC_Dat
	msgbox "Missing file " & chr(34) & CurrentDirectory &"\cc.dat" & chr(34) & ". Please get another copy from https://github.com/randomrhythm."
end if
'load country code dat
if objFSO.fileexists(CurrentDirectory &"\cc.dat") then
  Set objFile = objFSO.OpenTextFile(CurrentDirectory &"\cc.dat")
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        if instr(strData, "|") then
          strTmpArrayDDNS = split(strData, "|")
          if DictCC.exists(ucase(strTmpArrayDDNS(0))) = False then _
          DictCC.add ucase(strTmpArrayDDNS(0)), strTmpArrayDDNS(1)
          if DictRevCC.exists(strTmpArrayDDNS(1)) = False then _
          DictRevCC.add strTmpArrayDDNS(1), strTmpArrayDDNS(0)
        end if
        on error goto 0
    end if
  loop

end if

'load custom malware hash
LoadCustomDict CurrentDirectory &"\malhash.dat", DictMalHash
'load custom whitelist hash
LoadCustomDict CurrentDirectory &"\whitehash.dat", Dictwhitehash
'format for dictIPdomainWatchList is watchitem|note
LoadCustomDict CurrentDirectory &"\IPDwatchlist.txt", dictIPdomainWatchList
LoadCustomDict CurrentDirectory & "\generics.alias", dictGenericLabel
LoadWatchlist CurrentDirectory &"\DNwatchlist.txt", dictDnameWatchList
LoadWatchlist CurrentDirectory & "\KWordwatchlist.txt", dictKWordWatchList
LoadWatchlist CurrentDirectory &"\URLwatchlist.txt", dictURLWatchList



LoadEncyclopedia_Cache 'populates encyclopedia dictionaries DictMicrosoftEncyclopedia


'for loop to load API keys
for intCountVendors = 0 to 13 'Count of vendor APIs
	boolVendorEnabled = True
  if BoolDisableVTlookup = True and intCountVendors = 0 then 
	intCountVendors = 1
  end if
  if (objFSO.fileexists(CurrentDirectory & "\meta.disable") or BoolEnableMetascan = False) and intCountVendors = 1 then 
    intCountVendors = 2
    BoolEnableMetascan = False
  end if
  if (objFSO.fileexists(CurrentDirectory & "\tg.disable") or BoolEnableThreatGRID = False) and intCountVendors = 2 then 
    intCountVendors = 3
    BoolUseThreatGRID = False

    BoolUseThreatGRID_IP = False
    BoolEnableThreatGRID = False
  end if
  if (objFSO.fileexists(CurrentDirectory & "\cif.disable") or BoolEnableCIF = False) and intCountVendors = 3 then 
    BoolUseCIF = False  
    BoolEnableCIF = False
    intCountVendors = 4

  end if  
  if (objFSO.fileexists(CurrentDirectory & "\mals.disable") or boolEnableMalShare = False) and intCountVendors = 4 then 
    BoolUseMalShare = False  
    boolEnableMalShare = False
    intCountVendors = 5

  end if  
  if (objFSO.fileexists(CurrentDirectory & "\cb.disable") or BoolEnableCarbonBlack = False) and intCountVendors = 5 then 
    BoolEnableCarbonBlack = False  
    intCountVendors = 6

  end if
  if (objFSO.fileexists(CurrentDirectory & "\pp.disable") or BoolUseETIntelligence = False) and intCountVendors = 6 then 
    BoolUseETIntelligence = False  
    intCountVendors = 7

  end if
  if (objFSO.fileexists(CurrentDirectory & "\pt.disable") or boolEnablePassiveTotal = False) and intCountVendors = 7 then 
    boolEnablePassiveTotal = False  
    intCountVendors = 8

  end if
  if (boolEnableWhoAPI = false or objFSO.fileexists(CurrentDirectory & "\wa.disable")) and intCountVendors = 8 then 
    boolEnableWhoAPI = False  
    intCountVendors = 9

  end if    
   if (objFSO.fileexists(CurrentDirectory & "\da.disable") or BoolEnableDomainAPI = False) and intCountVendors = 9 then 
    BoolEnableDomainAPI = False  
    intCountVendors = 10

  end if    
 if (objFSO.fileexists(CurrentDirectory & "\tia.disable") or BoolEnableTIA = False) and intCountVendors = 10 then 
    BoolEnableTIA = False  
	intCountVendors = 11
  end if  
   
    if intCountVendors = 11 And BoolSeclytics = false then 
		intCountVendors = 12
	End if	
    if intCountVendors = 12 And (boolPulsedive = false Or PulsediveAPIprompt = False) Then 
		intCountVendors = 13
  	end if
   If (boolUseAlienVault = false or objFSO.fileexists(CurrentDirectory & "\av.disable")) and intCountVendors = 13 then 
     useAlienVapiKey = False
	 boolAlienVaultNIDS = False 'need an API key for this to work
	 boolAlienHostCheck = False 'Don't want to go over query threshold so disabled without API key
    exit for'Only exit on the last intCountVendors item
  end if  
  strDisableFile = ""
  if intCountVendors = 0 then
    strFile= CurrentDirectory & "\vt.dat"
    strAPIproduct = "virustotal.com"
  elseif intCountVendors = 1 then
    strFile= CurrentDirectory & "\meta.dat"
    strAPIproduct = "Metadefender"
	strDisableFile = CurrentDirectory & "\meta.disable"
  elseif intCountVendors = 2 then
    strFile= CurrentDirectory & "\tg.dat"
    strAPIproduct = "ThreatGRID"
	strDisableFile = CurrentDirectory & "\tg.disable"
  elseif intCountVendors = 3 then
    strFile= CurrentDirectory & "\cif.dat"
    strAPIproduct = "CIF"    
	strDisableFile = CurrentDirectory & "\cif.disable"
  elseif intCountVendors = 4 then
    strFile= CurrentDirectory & "\malshare.dat"
    strAPIproduct = "MalShare" 
	strDisableFile = CurrentDirectory & "\mals.disable"
  elseif intCountVendors = 5 then
    strFile= CurrentDirectory & "\cb.dat"
    strAPIproduct = "Carbon Black" 
  elseif intCountVendors = 6 then
    strFile= CurrentDirectory & "\pp.dat"
    strAPIproduct = "ET Intelligence" 
  elseif intCountVendors = 7 then
    strFile= CurrentDirectory & "\pt.dat"
    strAPIproduct = "PassiveTotal" 
	strDisableFile = CurrentDirectory & "\pt.disable"
  elseif intCountVendors = 8 then
    strFile= CurrentDirectory & "\wa.dat"
    strAPIproduct = "WhoAPI" 
	strDisableFile = CurrentDirectory & "\wa.disable"
   elseif intCountVendors = 9 then
    strFile= CurrentDirectory & "\da.dat"
    strAPIproduct = "Domain API (freedomainapi.com)"  
	strDisableFile = CurrentDirectory & "\da.disable"
   elseif intCountVendors = 10 then
    strFile= CurrentDirectory & "\tia.dat"
    strAPIproduct = "ThreatIntelligenceAggregator.org"  
	strDisableFile = CurrentDirectory & "\tia.disable"
   elseif intCountVendors = 11 then
    strFile= CurrentDirectory & "\scl.dat"
    strAPIproduct = "Seclytics"  
	strDisableFile = CurrentDirectory & "depreciated"   
   elseif intCountVendors = 12 then
    strFile= CurrentDirectory & "\pd.dat"
    strAPIproduct = "Pulsedive"  
	strDisableFile = CurrentDirectory & "depreciated"
   ElseIf intCountVendors = 13 then
    strFile= CurrentDirectory & "\av.dat"
    strAPIproduct = "AlienVault"  
	strDisableFile = CurrentDirectory & "\av.disable"
   end if

strData = ""
  if objFSO.fileexists(strFile) then
    Set objFile = objFSO.OpenTextFile(strFile)
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        if intCountVendors = 5 then 
          StrBaseCBURL = objFile.ReadLine
        elseif intCountVendors = 7 then
          strPTAPIuser = objFile.ReadLine 
        end if  
        on error goto 0
    end if
    if strData <> "" then
      strData = Decrypt(strData,strRandom)
        strTempAPIKey = strData
        strData = ""
    end if
  end if

  if not objFSO.fileexists(strFile) and strData = "" and objFSO.fileexists(strDisableFile) = False Then
    
      strTempAPIKey = inputbox("Enter your " & strAPIproduct & " api key")
      if strTempAPIKey <> "" then
      	strTempEncryptedAPIKey = strTempAPIKey
      	strTempEncryptedAPIKey = Trim(strTempEncryptedAPIKey)'remove spaces from the ends
        strTempEncryptedAPIKey = encrypt(strTempEncryptedAPIKey,strRandom)
        logdata strFile,strTempEncryptedAPIKey,False
        strTempEncryptedAPIKey = ""
        If intCountVendors = 3 Then
          strCIFurl = inputbox("Enter your " & strAPIproduct & " base URL (example: https://domain.com/indicators")
          if instr(strCIFurl, " ") then strCIFurl = replace(StrBaseCBURL, " ", "")
          UpdateIni CurrentDirectory & "\vttl.ini", "CIF_URL=" & strCIFurl ,"[vendor]" 
        ElseIf intCountVendors = 5 then
          StrBaseCBURL = inputbox("Enter your " & strAPIproduct & " base URL (example: https://ryancb-example.my.carbonblack.io")
          if instr(StrBaseCBURL, " ") then StrBaseCBURL = replace(StrBaseCBURL, " ", "")
          logdata strFile,StrBaseCBURL,False
        end if 
        if intCountVendors = 7 then
          strPTAPIuser = inputbox("Enter your " & strAPIproduct & " user name (typically email address)")
          if instr(strPTAPIuser, " ") then strPTAPIuser = replace(strPTAPIuser, " ", "")
          logdata strFile,strPTAPIuser,False
        end if 
      end if

   
	  if strTempAPIKey = "" then
		if intCountVendors = 0 then
		  msgbox "invalid api key"
		  'wscript.quit(999)
		   BoolDisableVTlookup = True 
		elseif intCountVendors = 1 then
		  BoolMetascan = False
		  intAnswer = msgbox ("Continuing without Metascan Online check. Do you want to disable Metascan Online lookups in the future?",vbYesNo, "VTTL Metacan Online Lookups")
		  if intAnswer = vbYes Then logdata CurrentDirectory & "\meta.disable", "Metacan Online lookups disabled" ,False 
		  BoolUseMetadefender = false
		elseif intCountVendors = 2 and BoolUseThreatGRID = True then
		  intAnswer = msgbox ("Continuing without ThreatGRID check. Do you want to disable ThreatGRID lookups in the future?",vbYesNo, "VTTL ThreatGRID Lookups")
		  BoolUseThreatGRID = False
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "enable_ThreatGRID=False" ,"[vendor]" 

		elseif intCountVendors = 3 and BoolUseCIF = True Then
		  intAnswer = msgbox ("Continuing without CIF check. Do you want to disable CIF lookups in the future?",vbYesNo, "VTTL CIF Lookups")
		  if intAnswer = vbYes Then  UpdateIni CurrentDirectory & "\vttl.ini", "UseCIF=False" ,"[vendor]" 
		  BoolUseCIF = False      
		elseif intCountVendors = 4 and BoolUseMalShare = True then
		  intAnswer = msgbox ("Continuing without MalShare check. Do you want to disable MalShare lookups in the future?",vbYesNo, "VTTL MalShare Lookups")
		  if intAnswer = vbYes Then  UpdateIni CurrentDirectory & "\vttl.ini", "enable_MalShare=False" ,"[vendor]" 
		  BoolUseMalShare = False  
		 elseif intCountVendors = 5 and BoolEnableCarbonBlack = True then
		  intAnswer = msgbox ("Continuing without Carbon Black check. Do you want to disable Carbon Black lookups in the future?",vbYesNo, "VTTL Carbon Black Lookups")
		  if intAnswer = vbYes Then  UpdateIni CurrentDirectory & "\vttl.ini", "enable_CarbonBlack=False" ,"[vendor]" 
		  BoolEnableCarbonBlack = False
		
		elseif intCountVendors = 6 and boolEnableETIntelligence = True Then
		  intAnswer = msgbox ("Continuing without ET Intelligence check. Do you want to disable ET Intelligence lookups in the future?",vbYesNo, "VTTL ET Intelligence Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "UseETIntelligence=False" ,"[vendor]" 
		  BoolUseETIntelligence = False  
		elseif intCountVendors = 7 and boolEnablePassiveTotal = True then
		  intAnswer = msgbox ("Continuing without PassiveTotal check. Do you want to disable PassiveTotal lookups in the future?",vbYesNo, "VTTL PassiveTotal Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "EnablePassiveTotal=False" ,"[vendor]" 
		  BoolUsePassiveTotal = False  
		elseif intCountVendors = 8 and boolEnableWhoAPI = True then
		  intAnswer = msgbox ("Continuing without WhoAPI check. Do you want to disable WhoAPI lookups in the future?",vbYesNo, "VTTL WhoAPI Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "EnableWhoAPI=False" ,"[vendor]"     
		  boolEnableWhoAPI = False
		elseif intCountVendors = 9 and BoolEnableDomainAPI = True then
		  intAnswer = msgbox ("Continuing without Domain API check. Do you want to disable Domain API lookups in the future?",vbYesNo, "VTTL Domain API Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "EnableDomainAPI=False" ,"[vendor]"     
		  BoolEnableDomainAPI = False
		elseif intCountVendors = 10 and boolEnableTIA = True then
		  intAnswer = msgbox ("Continuing without TIA API check. Do you want to disable TIA API lookups in the future?",vbYesNo, "VTTL TIA API Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "enable_TIA=False" ,"[vendor]"     
		  boolEnableTIA = False	  
		elseif intCountVendors = 11 and BoolSeclytics = True then
		  intAnswer = msgbox ("Continuing without Seclytics API check. Do you want to disable Seclytics API lookups in the future?",vbYesNo, "VTTL Seclytics API Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "useSeclytics=False" ,"[vendor]"     
		  BoolSeclytics = False	  
		elseif intCountVendors = 12 and boolPulsedive = True And PulsediveAPIprompt = True then
		  'API key is not required.
		  intAnswer = msgbox ("Continuing without Pulsedive API key. Do you want to disable Pulsedive API key prompts in the future?",vbYesNo, "VTTL Pulsedive API Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "PulsediveAPIprompt=False" ,"[vendor]"     
		  'boolPulsedive = False
		elseif intCountVendors = 13 and useAlienVapiKey = True then
		  intAnswer = msgbox ("Continuing without AlienVault API key. Do you want to disable this AlienVault API key prompt in the future?",vbYesNo, "VTTL AlienVault API Lookups")
		  if intAnswer = vbYes Then UpdateIni CurrentDirectory & "\vttl.ini", "use_AlienVaultAPIkey=False" ,"[vendor_AlienVault]"     
		  useAlienVapiKey = False	  
		end if
	  end If ' if strTempAPIKey <> "" then
  end If 'if strTempAPIKey = "" then
  if intCountVendors = 0 then
	strAPIKey = strTempAPIKey
  elseif intCountVendors = 1 and BoolEnableMetascan = True then
      strMetaAPIkey = strTempAPIKey
    if strMetaAPIkey <> "" then BoolMetascan = True
  elseif intCountVendors = 2 and BoolEnableThreatGRID = True then
      strTGAPIkey = strTempAPIKey
    if strTGAPIkey <> "" then 
      BoolUseThreatGRID = True
      boolTGwasEnabled = True
    end if
  elseif intCountVendors = 3 and BoolEnableCIF = True then 'boolEnable allows a vendor to be used. boolUse means the vendor has everything required to be used.
	strCIF_APIkey = strTempAPIKey
    if strCIF_APIkey <> "" then BoolUseCIF = True    
  elseif intCountVendors = 4 and boolEnableMalShare = True then
	strMalShareAPIKey = strTempAPIKey
    if strMalShareAPIKey <> "" then BoolUseMalShare = True    
  elseif intCountVendors = 5 and BoolEnableCarbonBlack = True then
      strCarBlackAPIKey = strTempAPIKey
    if instr(lcase(StrBaseCBURL),".") <> 0 and instr(lcase(StrBaseCBURL),"http") <> 0 and instr(lcase(StrBaseCBURL),"://") <> 0 then
      if strCarBlackAPIKey <> "" and StrBaseCBURL <> "" then BoolUseCarbonBlack = True   
    else
      msgbox "Invalid URL specified for Carbon Black: " & StrBaseCBURL
      StrBaseCBURL = "" 
      BoolUseCarbonBlack = False
	  BoolEnableCarbonBlack = False
    end if
  elseif intCountVendors = 6 and boolEnableETIntelligence = True then
	strETIntelligenceAPIKey = strTempAPIKey
    if strETIntelligenceAPIKey <> "" then BoolUseETIntelligence = True   
  elseif intCountVendors = 7 then 'PassiveTotal
	strPTAPIkey = strTempAPIKey
    if instr(lcase(strPTAPIuser),"@") <> 0 and instr(lcase(strPTAPIuser),".") <> 0 then
      if strPTAPIkey <> "" and strPTAPIuser <> "" and boolEnablePassiveTotal = True then BoolUsePassiveTotal = True   
    else
      if strPTAPIkey <> "" then msgbox "Invalid email address: " & strPTAPIuser
      strPTAPIuser = "" 
      BoolUsePassiveTotal = False
    end if  
  elseif intCountVendors = 8 and boolEnableWhoAPI = True then
	strWAPIkey = strTempAPIKey
  elseif intCountVendors = 9 and boolEnableDomainAPI = True then
	strWAPIkey = strTempAPIKey
  elseif intCountVendors = 10 and boolEnableTIA = True then
	strTIAkey = strTempAPIKey
  elseif intCountVendors = 11 and BoolSeclytics = True then
	SeclyApikey = strTempAPIKey
  elseif intCountVendors = 12 and boolPulsedive = True then
		PulsediveApikey = strTempAPIKey
  elseif intCountVendors = 13 and useAlienVapiKey = True then
	strAlienVaultkey = strTempAPIKey
  end if
  on error resume next
  objFile.close
  on error goto 0
  strTempAPIKey = ""
next

if BoolEnableTIA = False then
	boolCheckDrWeb = False 'Check for Dr Web write-up (requires TIA API)
	boolCheckAvira = False 'Check for Avira write-up (requires TIA API)
	boolCheckSymantec = False 'Check for Symantec write-up (requires TIA API)
	boolCheckFSecure = False 'Lookup F-Secure write-ups via Threat Intelligence Aggregator
	boolCheckBitdefender = False 'Lookup Bitdefender write-ups via Threat Intelligence Aggregator
	boolCheckPanda = False 'Lookup Panda write-ups via Threat Intelligence Aggregator
	boolCheckSophos = False ' requires TIA API
	boolCHeckMcAfee = False ' requires TIA API 
	boolCheckMicrosoft = False ' requires TIA API
	BoolCheckTrendMicro = False ' requires TIA API
	boolCheckESET = False ' requires TIA API
end if

if strCIFurl = "" then' URL to use for CIF requests (supports v2 currently) example: https://domain.com/indicators
	BoolEnableCIF = False 'Perform queries against CIF. Disabled if no API key provided
end if

'load no submit list to dictionary
LoadWatchlist CurrentDirectory &"\VTTL_NoSubmit.txt", dictNoSubmit

'load no domain submit list to dictionary
LoadWatchlist CurrentDirectory &"\VTTL_domains.txt", dictNoDomainSubmit


'Read list of items to submit to VT
if not objFSO.fileexists(CurrentDirectory & "\vtlist.txt") then
  objFSO.CreateTextFile CurrentDirectory & "\vtlist.txt", True
   objShellComplete.run "notepad.exe " & chr(34) & CurrentDirectory & "\vtlist.txt" & chr(34)
  msgbox "VTTL scan list (" & CurrentDirectory & "\vtlist.txt" & ") file was not found. The file has been created and opened in notepad. Please input the hashes or IP and domain addresses you want to scan and save the file." 
end if
Set oFile = objFSO.GetFile(CurrentDirectory & "\vtlist.txt")

	If oFile.Size = 0 Then
    objFSO.CreateTextFile CurrentDirectory & "\vtlist.txt", True
   objShellComplete.run "notepad.exe " & chr(34) & CurrentDirectory & "\vtlist.txt" & chr(34)
  msgbox "VTTL scan list (" & CurrentDirectory & "\vtlist.txt" & ") file was empty. The file has been opened in notepad. Please input hashes or IP addresses and domains you want to scan and save the file." 

	End If
Set oFile = objFSO.GetFile(CurrentDirectory & "\vtlist.txt")

	If oFile.Size = 0 Then

  msgbox "VTTL scan list (" & CurrentDirectory & "\vtlist.txt" & ") file was empty. The script has nothing to scan so will now exit.  Please input hashes or IP addresses and domains you want to scan and save the file." 
  wscript.quit(777)
	End If
strFile= CurrentDirectory & "\vtlist.txt"


if BoolCreateSpreadsheet = True then
  'initialize spreadsheet for data output
  intVTListDataType = ParseVTlist(strFile)'Check what kind of data will be processed and set appropiate header row
  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "_Parameter" & ".txt", "intVTListDataType=" & intVTListDataType ,BoolEchoLog 
  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "_Parameter" & ".txt", "BoolUseExcel=" & BoolUseExcel ,BoolEchoLog 
  'domain/IP address processing is not compatible with CSV format as it may contain return characters.
  'intVTListDataType 0=unknown, 1 domain/IP, 2=hash, 3=hash/domain/ip

  if intVTListDataType = 2 Then
    if BoolSigCheckLookup = True then loadSigCheckData strSigCheckFilePath, false
    if BoolEnCaseLookup = True then loadEncaseData
    if BoolSigCheckLookup = False and BoolEnCaseLookup = False then
      BoolAddStats = False
    end if
  else
    BoolAddStats = False
  end if
  if BoolUseExcel = True then
    on error resume next
    Set objExcel = CreateObject("Excel.Application")
    if err.number = 0 then
    on error goto 0
      LoadAlphabet
      objExcel.Visible = True
      Set objWorkbook = objExcel.Workbooks.Add()
      objExcel.Worksheets(intTabCounter).Name = "Threat Intelligence"
    else
      intAnswer = msgbox ("Problem creating Excel object. Do you want to create a CSV?",vbYesNo, "VTTL")
      if intAnswer = vbYes Then 
        BoolUseExcel = False
      else
        msgbox "the script will now exit"
        wscript.quit
      end if
    end if
  end if
  if objFSO.fileexists(strFile) then
    if BoolUseThreatGRID = True then
      strTmpTGhead = "|ThreatGRID"
    else
      strTmpTGhead = ""
    end if  
    if BoolEnableMetascan = True then
      strTmpMetahead = "|Metadefender"
    else
      strTmpMetahead = ""
    end if 

    if boolUsePassiveTotal = True then
      strTmpPThead = "|PassiveTotal"
    else
      strTmpPThead = ""
    end if

    if boolEnableCuckoo = True then
      strTmpCuckooHead = "|Cuckoo Score"
    else
      strTmpCuckooHead = ""
    end if
    if BoolUseETIntelligence = True then
      strTmpETIhead = "|ET Intelligence"
      if boolCheckProofpointIDS = True then 
        strTmpETIdshead = "|ET IDS"
      else
        strTmpETIdshead = ""
      end if
    else
      strTmpETIhead = ""
      strTmpETIdshead = ""
    end if
	
	strTmpAlienHead1 = ""
	strTmpAlienHead2 = ""
	if boolUseAlienVault = True then 
		strTmpAlienHead1 = "|AlienVault Pulse"
	end If
	if boolUseAlienVault = True Or BoolSeclytics = True Or boolPulsedive = True Then
		strTmpAlienHead2 ="|Validation"
		if dictKWordWatchList.count > 0 then
			strTmpKeyWordWatchListHead = "|Keyword Watch List"
		else
			strTmpKeyWordWatchListHead = ""
		end If
	End if	
	

	
	if boolUseThreatCrowd = True then
		strTmpTCrowdHead = "|ThreatCrowd"
	else
		strTmpTCrowdHead = ""
	end if
	strDetectWatchListHead  = ""
    select case intVTListDataType
      case 1 'ip/domain
        LoadIPAuthorities 'populates Dictripe, DictArin, etc
		if boolUseTrancoList = True and boolTrancoSQL = False then LoadTrancoList CurrentDirectory &"\top-1m.csv", dictTrancoList 'whitelist
        if cint(intDetectionNameCount) > 0 then'set modified for number of columns
          intaddDNameCount = round(intDetectionNameCount /2 +.1) 'round up to add additional column(s) for IP/Domain detection name association
          if dictDnameWatchList.count > 0 then strDetectWatchListHead  = "|Detection Name Watch List"
        end if

        if dictURLWatchList.count > 0 Then
          strTmpURLWatchListHead = "|URL Watch List"
        else
          strTmpURLWatchListHead = ""
        end if
        if dictIPdomainWatchList.count > 0 then 
          strTmpIpDwatchListHead = "|IP Domain Watch List"
        else
          strTmpIpDwatchListHead = ""
        end if

		if enableZEN = True then
			strZRBL = "|Spamhaus ZEN RBL"
		else
			strZRBL = ""
		end if
		if boolEnableZDBL = True then
			strZDBL = "|Spamhaus DBL"
		else
			strZDBL = ""
		end if
		
		if enableURIBL = True then
			strURIBL = "|URIBL"
		else
			strURIBL = ""
		end if
		if enableSURBL = True then
			strSURBL = "|SURBL"
		else
			strSURBL = ""
		end if
		if EnableBarracuda = True then
			strBarracudaDBL = "|Barrucda"
		else
			strBarracudaDBL = ""
		end if
		if EnableCBL = True then
			strCBL = "|CBL"
		else
			strCBL = ""
		end if
		if BoolUseCIF = True then
			strCIF = "|CIF"
		else
			strCIF = ""
		end if
		if enableSORBS = True then  
			strSORBSline = "|SORBS"
		else
			strSORBSline = ""
		end if
		if boolUseQuad9 = True then
			strQuad9Head = "|Quad9"
		else
			strQuad9Head = ""
		end if
		if boolAlienVaultNIDS = True then
			alienNIDShead = "|NIDS Count|NIDS Categories|AlienVault NIDS"
		else
			alienNIDShead = ""
		end if
		if boolUseTrancoList = True then
			TrancoHead = "|Tranco_list"
		else
			TrancoHead = ""
		end If
		
		If BoolSeclytics = True Then
			SeclytHead = "|Seclytics Reputation and Reason|Seclytics Associated File Metadata|Seclytics File Count"
	        if dictDnameWatchList.count > 0 then strDetectWatchListHead  = "|Detection Name Watch List"
 
		Else
			SeclytHead = ""
		End If	
		if boolPulsedive = True then
      PulsediveHead = "|Pulsedive|SSL Subject|SSL Org"
		else
      PulsediveHead = ""
		end if
        DetectionNameHeaderColumns = DetectionNameHeader 'header row for IP/Domain detection names
		if BoolDisableVTlookup = False then
			strVThead = "Scanned Item|VTTI Download From|VTTI Referrer|VTTI Callback To|VTTI_Uniq_URLs|VTTI_Uniq_Domains"
			vtHead2 = "|VT Download|VT Referrer|VT Callback|VT URL"
		else
			strVThead = "Scanned Item"
			vtHead2 = ""
		end if
            'write IP/domain header row
        Write_Spreadsheet_line(strVThead & TrancoHead & strTmpETIhead & strSORBSline & strQuad9Head & strCBL & strBarracudaDBL & strZRBL & strZDBL & strURIBL & strSURBL & strTmpTGhead & strCIF & strTmpMetahead & "|Country Name|Country Code|Region Name|Region Code|City Name|Creation Date|Reverse DNS|WHOIS|Hosted Domains|IP Address" & strTmpXforceHead & "|Category|DDNS" & strTmpTCrowdHead & strTmpAlienHead1 & strTmpAlienHead2 & strTmpKeyWordWatchListHead & vtHead2 & "|Restricted Domain|Sinkhole|Cache" & DetectionNameHeaderColumns & strTmpIpDwatchListHead & strDetectWatchListHead  & strTmpURLWatchListHead & strTmpETIdshead & alienNIDShead & SeclytHead & PulsediveHead)
        if BoolCreateSpreadsheet = True then
          if cint(intDetectionNameCount) > 0 then 
            
            redim ArrayDnameLineE(cint(intDetectionNameCount) -1 + intaddDNameCount)
          end if
          if BoolUseExcel = True then
            mycolumncounter = 1
            Do while objExcel.Cells(1,mycolumncounter).Value <> ""
              if objExcel.Cells(1,mycolumncounter).Value = "CIF" then
                if BoolUseCIF = True then sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 25
              end if
              if objExcel.Cells(1,mycolumncounter).Value = "Metadefender" then
                if BoolMetascan = True then sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 25
              end if
              if objExcel.Cells(1,mycolumncounter).Value = "RBL_Spamhaus ZEN" then
                if BoolDNS_BLchecks = True then sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 18
              end if
              if objExcel.Cells(1,mycolumncounter).Value = "Creation Date" then
                sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 17
              end if
              if objExcel.Cells(1,mycolumncounter).Value = "Category" then
                sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 17
              end if
              
              if objExcel.Cells(1,mycolumncounter).Value = "ET Intelligence" then
                if BoolUseETIntelligence = True then sbChangeColumnWidth DictAlpabet.item(mycolumncounter), 17
              end if
              mycolumncounter = mycolumncounter + 1
            loop
          end if
        else
          intDetectionNameCount = 0 'zero out to disable IP/domain detection name hash lookups
        end if
      case 2 'Hash lookups only                                                                                       'hash lookups only
        intDetectionNameCount = 0 'zero out to disable IP/domain detection name hash lookups
        boolLogHashes = false 'Don't log hashes if that is what we are looking up
        if BoolSigCheckLookup = True and BoolUseCarbonBlack = True then
          strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|CB Prevalence|File Size|Digial Signature Tracking"
        elseif BoolEnCaseLookup = True and BoolUseCarbonBlack = True then
          strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|CB Prevalence|File Size|Digial Signature Tracking"
        elseif BoolUseCarbonBlack = True then
          strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|CB Prevalence|File Size|Digial Signature Tracking"
        elseif BoolSigCheckLookup = True then
          if cint(inthfPrevalenceLoc) > -1 then 'CB custom CSV export
            strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|CB Prevalence|File Size|Digial Signature Tracking"
          elseif boolEnableCuckoo = True or (BoolDisableVTlookup = False and boolVTuseV3 = True) then
            strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|File Size|Digial Signature Tracking"
          else
            strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|Digial Signature Tracking"
          end if
          if cint(intHostLocation) > 0 then
            strTmpCBHead = strTmpCBHead & "|Hosts"
          end if
          if BoolSigCheckLookup = True and BoolUseCarbonBlack = False and boolEnableCuckoo = False then
            'crowdstrike csv export does not support any of these
            if inthfSizeLoc = -1 and (boolVTuseV3 = False or BoolDisableVTlookup = True) then strTmpCBHead = replace(strTmpCBHead, "|File Size","")
            if intPublisherLoc = -1 then strTmpCBHead = replace(strTmpCBHead, "|Digital Sig","")
            if intPublisherLoc = -1 then strTmpCBHead = replace(strTmpCBHead, "|Digial Signature Tracking","")			
            if inthfProductLoc = -1 then strTmpCBHead = replace(strTmpCBHead, "|Product Name","")
            if intCompanyLoc = -1 then strTmpCBHead = replace(strTmpCBHead, "|Company Name","")
          end if

        elseif boolEnableCuckoo = True then 
          strTmpCBHead = "|Digital Sig|Company Name|Product Name|File Size|Digial Signature Tracking"
          'StrTmpCTimeStamp = "|PE TimeStamp"
        elseif BoolDisableVTlookup = False and boolVTuseV3 = True Then
        	strTmpCBHead = "|File Path|Digital Sig|Company Name|Product Name|File Size|Digial Signature Tracking"
        elseif BoolEnCaseLookup = True then
          strTmpCBHead = "|File Path|File Size"
        ElseIf boolEnableCuckooV2 = True then   
			strTmpCBHead = "|File Size"
        Else
          strTmpCBHead = ""
          StrTmpCTimeStamp = ""
          strYARAhead = ""
        end if
        if boolEnableCuckoo = True then
          strYARAhead = "|YARA"
          strFileTypeHead = "|File Type"
        else
          strYARAhead = ""
          strFileTypeHead = ""
        end if
		if boolEnableCuckooV2 = True Or (BoolDisableVTlookup = False and boolVTuseV3 = True) then 
          strFileTypeHead = "|File Type"
	    end If
	    if BoolDisableVTlookup = False and boolVTuseV3 = True Then
        	StrTmpCTimeStamp = "|PE TimeStamp"
        	strMimeTypeHead = "|File Insight"
        End if	
        if boolEnableMalShare = True then
          strTmpMalShareHead = "|MalShare"
        else
          strTmpMalShareHead = ""
        end if
        if boolCheckDrWeb = True then
          strTmpDrWebHead = "|Dr.Web"
        else
          strTmpDrWebHead = ""
        end if
        if boolCheckAvira = True then
          strTmpAviraHead = "|Avira"
        else
          strTmpAviraHead = ""
        end if
        if boolCheckSymantec = True then
          strTmpSymantecHead = "|Symantec"
        else
          strTmpSymantecHead = ""
        end if
		if boolCheckFSecure = True then 
			strTMpFSecureHead = "|F-Secure"
		else
			strTMpFSecureHead = ""
		end if 
		if boolCheckSophos = True then 
			strTMpSophosHead = "|Sophos"
		else
			strTMpSophosHead = ""
		end if
		if boolCHeckMcAfee = True then 
			strTMpMcAfeeHead = "|McAfee"
		else
			strTMpMcAfeeHead = ""
		end if
		if boolCheckMicrosoft = True then 
			strTMpMicrosoftHead = "|Microsoft"
		else
			strTMpMicrosoftHead = ""
		end if
		if BoolCheckTrendMicro = True then 
			strTMpTrendMicroHead = "|Trend Micro"
		else
			strTMpTrendMicroHead = ""
		end if
		if boolCheckESET = True then 
			strTMpESETHead = "|ESET"
		else
			strTMpESETHead = ""
		end if		
		if boolCheckBitdefender = True then
			strTmpBitdefenderHead = "|Bitdefender"
		else
			strTmpBitdefenderHead = ""
		end if
		if boolCheckPanda = True then 
			strTMpPandaHead = "|Panda"
		else
			strTMpPandaHead = ""
		end if 
		if DisplayVendor <> "" Then
			strTmpDispVendHead = "|" & DisplayVendor
		else
			strTmpDispVendHead = ""
		end if
		If BoolSeclytics = False Then
			SeclytHead = ""
		Else
			
	 		SeclytHead = "|Seclytics File Associated Metadata"
			if dictURLWatchList.count > 0 Then
	          strTmpURLWatchListHead = "|URL Watch List"
	        else
	          strTmpURLWatchListHead = ""
	        end if
	        if dictIPdomainWatchList.count > 0 then 
	          strTmpIpDwatchListHead = "|IP Domain Watch List"
	        else
	          strTmpIpDwatchListHead = ""
	        end If
	        if dictDnameWatchList.count > 0 then strDetectWatchListHead  = "|Detection Name Watch List"
	    End if    
		
		if dictDnameWatchList.count > 0 then strDetectWatchListHead  = "|Detection Name Watch List"
		'Write file hash header row
        Write_Spreadsheet_line("Hash|VT Scan|Mal Score|Generic Score|PUA Score|HKTL Score|Malicious" & strTmpMetahead & strTmpXforceHead & strTmpETIhead & strTmpTGhead & strTmpTCrowdHead & strTMpTrendMicroHead & strTMpMicrosoftHead & strTMpMcAfeeHead & strTMpSophosHead & strTmpSymantecHead & strTMpESETHead & strTmpAviraHead & strTmpDrWebHead & strTMpPandaHead & strTMpFSecureHead & strTmpBitdefenderHead & strTmpDispVendHead & strTmpAlienHead1 & "|Scan Date|Common Name|Detection Type|Cache" & strDetectWatchListHead  & strTmpMalShareHead & strTmpCBHead & strTmpCuckooHead & strTmpPThead & "|Date First Seen" & strYARAhead & strMimeTypeHead & strFileTypeHead & StrTmpCTimeStamp & strTmpETIdshead & SeclytHead & strTmpIpDwatchListHead & strTmpURLWatchListHead & strTmpKeyWordWatchListHead)
        BoolUseCIF = False 'don't use CIF when in spreadsheet mode and performing hash lookups
      case 3
        Wscript.echo "Can't process IP/domains along side hashes. Please remove hashes or include only hashes in vtlist.txt. If only contains hashes make sure each entire line contains valid hashes (extra, missing, invalid characters)."
        
        ExitExcel
        wscript.quit(747)
      case 4
        Wscript.echo "Data was found besides hashes. Please include only hashes or IP/domains in vtlist.txt. If only contains hashes make sure each entire line contains valid hashes (extra, missing, invalid characters)."
        
        ExitExcel
        wscript.quit(748)
      Case 0
        Wscript.echo "No data was found in vtlist.txt that can be scanned. If you are scanning a hash make sure the character length is appropiate (Example: 32 characters in MD5 hash). If scanning a domain or IP address please check your formatting."
        
        ExitExcel
        wscript.quit(746)    
    end select
    if BoolUseExcel = True then
      objExcel.Rows(2).Select
      objExcel.ActiveWindow.FreezePanes = True

    end if
  end if
end if


Set objFile = objFSO.OpenTextFile(strFile)



For xy = 0 to 8
  select case xy
    Case 0
      strTempCpath = "\vt"
    Case 1
      strTempCpath = "\ms"
    Case 2
      strTempCpath = "\xf"
    Case 3 
      strTempCpath = "\tg"
    Case 4
      strTempCpath = "\tc"
    Case 5 
      strTempCpath = "\te"
    Case 6
      strTempCpath = "\malshare"
    Case 7
      strTempCpath = "\cb"
    Case 8
      strTempCpath = "\es"
  end select  
    

  if objFSO.folderexists(strCachePath & strTempCpath) = False then _
  objFSO.createfolder(strCachePath & strTempCpath)
  if objFSO.folderexists(strCachePath & strTempCpath & "\md5") = False then _
  objFSO.createfolder(strCachePath & strTempCpath & "\md5")
  if objFSO.folderexists(strCachePath & strTempCpath & "\sha1") = False then _
  objFSO.createfolder(strCachePath & strTempCpath & "\sha1")
  if objFSO.folderexists(strCachePath & strTempCpath & "\sha256") = False then _
  objFSO.createfolder(strCachePath & strTempCpath & "\sha256")
  if objFSO.folderexists(strCachePath & strTempCpath & "\unknown") = False then _
  objFSO.createfolder(strCachePath & strTempCpath & "\unknown")

next

inLoopCounter = 0
intCountPendItems = 0


If BoolRunSilent = False and strSigCheckFilePath = "" then Msgbox "starting lookups"
Do While Not objFile.AtEndOfStream or boolPendingItems = True or boolPendingTIAItems = True
    if BoolSkipedVTlookup = true and sleepOnSkippedVT = True then 'If true a cached VT result was pulled
		inLoopCounter = inLoopCounter +1
		If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
	elseif BoolDisableVTlookup = True then
	  lookupDelay
	  strDateLookupTrack = Now 'set the date time when last lookup was performed for rate limit delay
    end if
    strData = ""
    boolsubmitVT = True
	etHashLookedUp = false
	tcHashLookedUp = False
    if not objFile.AtEndOfStream then 'read file
      On Error Resume Next
      do while DicScannedItems.Exists(strData) = True and objFile.AtEndOfStream = False or DicScannedItems.Exists(strData) = false and Not objFile.AtEndOfStream and strData = ""
        strData = objFile.ReadLine 'read in vtlist one line at a time
		if instr(strData, " ") then
			logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " line in vtlist.txt contained a space that will be removed: " & strData,False 
			strData = replace(strData, " ", "") 'space is not a supported character
		end if
        if isIPaddress(strData) then 
          if IsPrivateIP(strData) then strData = ""
          If IsIPv6(strData) Then
          	If InStr(strData, "::") Then 'double colon encountered - https://en.wikipedia.org/wiki/IPv6_address#Representation
			  v6Length = UBound(Split(strData, ":")) 'count hextets
			  strHexAdd = ""
			  For missingHextet = v6Length +1 To 8
			    strHexAdd = strHexAdd & ":0" 'build hextet to expand missing hex values required for checking IPv6 ranges
			  Next
			  strData = replace(strData, "::", strHexAdd & ":") 'replace double colon with expanded hextet(s)
			  if right(strData,1) = ":" then strData = strData & "0" 'expand last hextet
			End If
          End If
        end if
        if objFile.AtEndOfStream and DicScannedItems.Exists(strData) then strData = ""
        if IsHash(strData) = False and instr(strData,".") = 0 and instr(strData,":") = 0 then strData = ""
        if  strData = vbcrlf then strData = ""
        if instr(strData,"[") > 0 then strData = replace(strData,"[","")
        if instr(strData,"]") > 0 then strData = replace(strData,"]","")
      on error goto 0
      Loop
      if not DicScannedItems.Exists(strData) then _
        DicScannedItems.Add strData, DicScannedItems.Count end if
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "new item from vtlist " & strData,BoolEchoLog 
      
      if intVTListDataType = 1 then 'ip/domain
		  For each strTmpCompareDomain in dictNoDomainSubmit'Add sub domains to dictNoSubmit excluding from VTTL lookup 
			if len(strTmpCompareDomain) > 0 and len(strTmpCompareDomain) <= len(strData) then
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", lcase(right(strData, len(strTmpCompareDomain))) & " = " & lcase(strTmpCompareDomain),BoolEchoLog 
			  if lcase(right(strData, len(strTmpCompareDomain))) = lcase(strTmpCompareDomain) then
				boolsubmitVT = False
				if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "boolsubmitVT = False",BoolEchoLog 
			  end if
			end if
		  next
	  end if
    else'go through pending items
        strData = ""
		if BoolDebugTrace = True and boolEnableTIAqueue = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "DicPendingItems.count=" & DicPendingItems.count-1 & "  outQueue.count=" &  outQueue.count,BoolEchoLog 
        if boolRescan = True then wscript.sleep 30000
        boolRescan = False
        do while strData = "" and intCountPendItems <= DicPendingItems.count-1
          'msgbox intCountPendItems & " " & DicPendingItems.count & DicScannedItems.Exists(DicPendingItems.keys()(intCountPendItems))
          'msgbox DicPendingItems.keys()(intCountPendItems)
          if not DicScannedItems.Exists(DicPendingItems.keys()(intCountPendItems)) then
            if DicPendingItems.keys()(intCountPendItems) <> "" then
              DicScannedItems.Add DicPendingItems.keys()(intCountPendItems), DicScannedItems.Count 
              strData = DicPendingItems.keys()(intCountPendItems)
            end if
    
          end if
          intCountPendItems = intCountPendItems +1
          if intCountPendItems <= DicPendingItems.count-1 then exit do
        loop
        if intCountPendItems >= DicPendingItems.count then boolPendingItems = False
        
		if strData = ""  and boolEnableTIAqueue = True then 'empty tia queue
			'msgbox outQueue.count
			if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", outQueue.count & " items in the queue",BoolEchoLog 
			if outQueue.count > 0 then
				qCount = 0
				do while qCount <= outQueue.count
					wscript.sleep 16000
					qCount = qCount + 1
					Write_Spreadsheet_line "" 'calling write line with "" will process the queue
				loop
			end if
			exit do 'we are done  
		end if
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "new item from pending list " & strData,BoolEchoLog 
		
    end if
    if instr(strData,".") > 0 or instr(strData,":")  then 'submit to virustotal as a URL
      if BoolNoScanning = True or dictNoSubmit.Exists(strData) then
        strOptionalParameter = "&scan=0"
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "&scan=0",BoolEchoLog 
      else  
        strOptionalParameter = "&scan=1"
      end if
      strVT_APIurl = "http://www.virustotal.com/vtapi/v2/url/report?"
      BoolPost = true
      strDataType = "resource="
    elseif IsHash(strData) = True then
      strData= lcase(strData)
        strOptionalParameter = ""
		if boolVTuseV3 = True then
			strVT_APIurl = "https://www.virustotal.com/api/v3/files/"
			BoolPost = false
		else
			strVT_APIurl = "https://www.virustotal.com/vtapi/v2/file/report?"
			BoolPost = true
		end if
        
        strDataType = "resource="
        
    end if  

    strScanDataInfo = strData 
	if BoolWhoisDebug = True then msgbox "Read list item:" & strData
    
      if boolsubmitVT = True and (IsHash(strData) or BoolCreateSpreadsheet = False) = True then 
        VT_Submit 'submit to virustotal as a URL or File
        inLoopCounter = inLoopCounter + 1
        If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
      end if

	
	if (BoolDisableVTlookup = True Or boolsubmitVT = false) and IsHash(strData) = True Then
		AlienHashLookup(strData)
		        
        If Len(strData) = 32 Then 'md5 hash
	        'Threat Crowd lookups
	        If boolUseThreatCrowd = True And tcHashLookedUp = False Then 'only accepts md5
	           strTmpTCrowd = ThreatCrowdHashLookup(strData)      
	        end If
	        'Proofpoint ET Intelligence lookups
	        if BoolUseETIntelligence = True And etHashLookedUp = false Then 
	          PPointSubmit "md5"
	          if boolCheckProofpointIDS = True then strPPidsLineE = CheckProofpIDS("md5", strData)
	        end if 
	    End if 'end requirement for MD5 hash   
	    'CAPE - Cuckoo modified
	      If boolEnableCuckoo = True then
			CuckooHashSubmit strData
          end If
	    'Cuckoo v2
          if boolEnableCuckooV2 = True then
			strCuckooResponse = SubmitCuckooV2Hash(strData)
			ParseCuckooV2 strCuckooResponse
		  end If
		'MalShare
		if BoolUseMalShare = True then
          MalShareHashLookup  strScanDataInfo       
        end If
    elseif BoolDisableVTlookup = True and IsHash(strData) = False Then    
        whoIsPopulate strScanDataInfo
	End If
	
	If IsHash(strData) = True Then
		If BoolSeclytics = True Then 'set to true to use Seclytics
			SeclytReturnBody = httpget("https://api.seclytics.com/files/", strScanDataInfo,"?","access_token", SeclyApikey, false) 'get API results
			SeclyticsProcess(SeclytReturnBody) 'process API results populating dictionaries
			SeclytRepReason = dict2List(DicIP_Context, "^") 'create list from dict
			if len(SeclytRepReason) > 32767 then SeclytRepReason = truncateCell(SeclytRepReason)
			SeclytFileRep = dict2List(DicFile_Context, "^")
			SeclytFileDate SeclytReturnBody 'Populate first seen date
			KeywordSearch SeclytReturnBody 'keyword search watch list processing
			

		End If
	End If
	
    if inLoopCounter >= 4 then
      wscript.sleep 60000
      If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter greater than 4",False 
      inLoopCounter = 0
    end if
	If  ishash(strData) = False then
	  if BoolUseCIF = True Then
		if instr(strCIFoutput, "for " & strData & ":") = 0 then
			strTmpRequestResponse = SubmitCIF(strData)

			if strTmpRequestResponse <> "" and strTmpRequestResponse <> "Credential Error Accessing CIF" then
			  if strCIFoutput = "" then
				strCIFoutput = vbcrlf & "CIF results for " & strData & ":" & vbcrlf & strTmpRequestResponse & vbcrlf
			  else
				strCIFoutput = strCIFoutput & vbcrlf & "CIF results for " & strData & ":" & vbcrlf & strTmpRequestResponse & vbcrlf
			  end if
			  strTmpCIFlineE = "|" & strTmpRequestResponse
			else
			  strTmpCIFlineE = "|"
			end if
		end if
	  end If
		If boolPulsedive = True Then
		    PulsediveBody = httpget("https://pulsedive.com/api/info.php?indicator=", strScanDataInfo,"","key", PulsediveApikey, false) 'get API results
		    If instr(PulsediveBody, "Indicator not found.") = 0 Then
		     KeywordSearch PulsediveBody
				 strTmpPulsediveLineE = getdata(PulsediveBody, chr(34), "risk" & chr(34) & ":" & chr(34))
      RiskFactor = getdata(PulsediveBody, "]", "riskfactors" & chr(34) & ":[")
			if AlienVaultValidation = "" or AlienVaultValidation = "|" then
        if instr(RiskFactor, "top 100 domain") > 0 then
            AlienVaultValidation = "top 100 domain"
        elseif instr(RiskFactor, "top 1k domain") > 0 then
            AlienVaultValidation = "top 1k domain"
        elseif instr(RiskFactor, "top 10k domain") > 0 then
            AlienVaultValidation = "top 10k domain"		
        elseif instr(RiskFactor, "top 100k domain") > 0 then
            AlienVaultValidation = "top 100k domain"
        end if
      end if
				Check_name_server PulsediveBody
				If strTmpIPContactLineE = "" or strTmpIPContactLineE = "|" then
					strTmpIPContactLineE = WhoisPopulate (PulsediveBody) 'sets geolocation and whois contact
					if sslOrg = "" or sslSubject= "" then
            PulsediveSslPopulate PulsediveBody
					end if
        
				Else
					WhoisPopulate PulsediveBody
				End if	
			Else
				strTmpPulsediveLineE = ""

			End if
			
		end If
	End if	
	  
	  if isIPaddress(strData) and not dictIPreported.Exists(strData) then'only report on the IP once
           dictIPreported.add strData, 1
           strOptionalParameter = ""
          strVT_APIurl = "http://www.virustotal.com/vtapi/v2/ip-address/report?"  
          BoolPost = false
          strDataType = "ip="
        
        'set strTmpIPlineE and strRevDNS
        subReverseDNSwithSinkhole strData, "8.8.8.8"

        if boolsubmitVT = True then
          VT_Submit 
          inLoopCounter = inLoopCounter + 1
          If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
        end if
        'perform MetaScan Online scans of the IP address
        if BoolMetascan = True then
          'Grab data we process from MetaScan online submission output
          strTmpReturnedMetaScanIPData = SubmitMetaScan(strData)

          'Process data to be formatted for output
          StrProcessedMetaScanIPreturn = Process_MetaScanIP_Data
          'order results listing results with assessments first 
          if instr(StrProcessedMetaScanIPreturn, "MetaScan Online assessment:") then
            strMetaScanOnlineAssessments = strMetaScanOnlineAssessments & vbcrlf & strData & " " & StrProcessedMetaScanIPreturn
          elseif StrProcessedMetaScanIPreturn <> "" then   'order results listing results with assessments second 
            strMetaScanOnlineGeoIP =  strMetaScanOnlineGeoIP & vbcrlf & strData & " " & StrProcessedMetaScanIPreturn
          end if
          logdata strMetaReportsPath & "\Metascan_" & strData & ".txt", strMSfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog

          'Combine assessments and geoip results
          StrIPMetaScanFormatted = strMetaScanOnlineAssessments & strMetaScanOnlineGeoIP
        end if

        
        if BoolDNS_BLchecks = True then
          for RBL_loop = 0 to 5
			StrTmpRBLOutput = ""
            if RBL_loop = 0 and EnableCBL = True then StrTmpRBLOutput = RBL_Lookup(strData, ".cbl.abuseat.org" & cblDNS)
            if RBL_loop = 1 and EnableBarracuda = True then StrTmpRBLOutput = RBL_Lookup(strData, ".b.barracudacentral.org " & cudaDNS)
            'if RBL_loop = 2 then StrTmpRBLOutput = RBL_Lookup(strData, ".xbl.spamhaus.org")
            if RBL_loop = 2 and enableZEN = True then StrTmpRBLOutput = RBL_Lookup(strData, ".zen.spamhaus.org " & zenDNS)
            if boolDisableDomain_BLchecks = False then'Ip addresses not in all DNS block lists
				if RBL_loop = 3 and enableURIBL = True then StrTmpRBLOutput = RBL_Lookup(strData, ".multi.uribl.com " & uriblDNS )
				if RBL_loop = 4 and enableSURBL = True then StrTmpRBLOutput = RBL_Lookup(strData, ".multi.surbl.org " & surblDNS)
			elseif RBL_loop = 3 or RBL_loop = 4 then
				StrTmpRBLOutput = ""
			end if
			if RBL_loop = 5 and enableSORBS = True then  RBL_Lookup strData, ".dnsbl.sorbs.net " & SorbsDNS
            if StrTmpRBLOutput <> "" then
              if StrRBL_Results = "" then
                StrRBL_Results = StrTmpRBLOutput
              else
                StrRBL_Results = StrRBL_Results & vbcrlf & StrTmpRBLOutput
              end if
              if RBL_loop = 0 then strTmpCBLlineE = "|X"
              if RBL_loop = 1 then strTmpCudalineE = "|X"

              if RBL_loop = 2 then 
                if instr(StrTmpRBLOutput, " as ") then
                  
                  strTmpZENlineE = right(StrTmpRBLOutput, (len(StrTmpRBLOutput) - instr(StrTmpRBLOutput, " as ")) -3 )
                  strTmpZENlineE = "|" & left(strTmpZENlineE, len(strTmpZENlineE) -2)
                else
                     strTmpZENlineE = "|X"
                End if
              end if
              if RBL_loop = 3 then strTmpURIBLlineE = "|X"

            end if
         next 
       end If
       
		
	   'Threat Crowd lookups
        if boolUseThreatCrowd = True then
           strTmpTCrowd = CheckThreatCrowd("ip", strData)
         logdata strIPreportsPath & "\TCrowd_IP_" & strData & ".txt", strScanDataInfo & vbtab & strTmpTCrowd,BoolEchoLog 
         if strTmpTCrowd <> "" then
          if strTCrowd_Output = "" then
            strTCrowd_Output = "https://www.threatcrowd.org/ip.php?ip=" & strData
          else
            strTCrowd_Output = strTCrowd_Output & vbcrlf & "https://www.threatcrowd.org/ip.php?ip=" & strData
          end if
          strTMPTCrowdLine = "|X"
         end if
        end If

		if BoolUseThreatGRID = True and BoolUseThreatGRID_IP = True then
          strTmpRequestResponse = SubmitThreatGRID(strScanDataInfo)
          if strTmpRequestResponse <> "" then
            if strTmpRequestResponse <> "ThreatGRID has never seen this file hash" and strTmpRequestResponse <> "ThreatGRID won't give results back" then
              if strThreatGRID_Output = "" then
                strThreatGRID_Output = strTmpRequestResponse
              else
                  strThreatGRID_Output = strThreatGRID_Output & vbcrlf & strTmpRequestResponse
              end if
              strTmpTGlineE = "|X"

            else
              strTmpTGlineE = "|"
            end if
          end if
      end if

		'MsgBox "debug: boolUseAlienVault=" & boolUseAlienVault
		if boolUseAlienVault = True then'AlienVault general IP query provides owner and geoip as well as pulses and validation
			if isIpv6(strScanDataInfo) = True then
				strAlienVaultReturn = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/IPv6/", strScanDataInfo, "/general")
				if boolAlienVaultPassiveDNS = True and instr(strAlienVaultReturn, chr(34) & "passive_dns" & chr(34)) > 0 then ProcessAlienVaultPdns "https://otx.alienvault.com/api/v1/indicators/IPv6/", strScanDataInfo
				if boolAlienVaultNIDS = True and strAlienVaultkey <> "" and instr(strAlienVaultReturn, chr(34) & "nids_list" & chr(34)) > 0 then ProcessAlienVaultNIDS "https://otx.alienvault.com/api/v1/indicators/IPv6/", strScanDataInfo
				strAlienHostURL = "https://otx.alienvault.com/api/v1/indicators/IPv6/"
			elseif isIPaddress(strScanDataInfo) = True then
				strAlienVaultReturn = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/IPv4/", strScanDataInfo, "/general")
				if boolAlienVaultPassiveDNS = True and instr(strAlienVaultReturn, chr(34) & "passive_dns" & chr(34)) > 0 then ProcessAlienVaultPdns "https://otx.alienvault.com/api/v1/indicators/IPv4/", strScanDataInfo
				'msgbox "alienNIDS:" & (boolAlienVaultNIDS = True and strAlienVaultkey <> "" and instr(strAlienVaultReturn, chr(34) & "nids_list" & chr(34)) > 0)
				if boolAlienVaultNIDS = True and strAlienVaultkey <> "" and instr(strAlienVaultReturn, chr(34) & "nids_list" & chr(34)) > 0 then ProcessAlienVaultNIDS "https://otx.alienvault.com/api/v1/indicators/IPv4/", strScanDataInfo
				strAlienHostURL = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
			end if
			if BoolDebugTrace = True then  logdata strIPreportsPath & "\AVault_IP_" & strData & ".txt", strScanDataInfo & vbtab & strAlienVaultReturn,BoolEchoLog 
			KeywordSearch strAlienVaultReturn 'keyword search watch list processing
			AlienVaultPulseLine = AlienPulse(strAlienVaultReturn)
			AlienVaultValidation = AlienValidation(strAlienVaultReturn)
			'MsgBox "debug: strTmpCClineE=" & strTmpCClineE
			if strTmpIPContactLineE = "" or strTmpIPContactLineE = "|" then
				strTmpIPContactLineE = AlienVaultWhois (strAlienVaultReturn) 'sets geolocation and whois contact
				if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "Alien Return: " & strTmpIPContactLineE, false
			elseif strTmpCClineE = "|" or strTmpWCO_CClineE = "|" then
				AlienVaultWhois strAlienVaultReturn
			end if
			if boolAlienHostCheck = True and instr(strAlienVaultReturn, chr(34) & "url_list" & chr(34)) > 0 then
				
				if strDomainListOut = "" or dictURLWatchList.count > 0 or boolLogURLs = True then
					strAlienHostURLs = pullAlienVault(strAlienHostURL, strScanDataInfo, "/url_list")
					ProcessAlienURLs strAlienHostURLs
				end if
			end if
		end if

		If BoolSeclytics = True Then 'set to true to use Seclytics
			SeclytReturnBody = httpget("https://api.seclytics.com/ips/", strScanDataInfo,"?","access_token", SeclyApikey, false) 'get API results
			SeclyticsProcess(SeclytReturnBody) 'process API results populating dictionaries
			SeclytRepReason = dict2List(DicIP_Context, "^") 'create list from dict
			if len(SeclytRepReason) > 32767 then SeclytRepReason = truncateCell(SeclytRepReason)

			SeclytFileRep = dict2List(DicFile_Context, "^")
			SeclytFileCount = getSeclyticFileCount(SeclytReturnBody)'get file count from number of hashes
			SeclytASN SeclytReturnBody 'populate IP owner field
			KeywordSearch SeclytReturnBody 'keyword search watch list processing
			SeclytWhitelist SeclytReturnBody 'Set validation if whitelisted
		End If
		


        if isIPaddress(strdata) and strTmpCNlineE = "|" and strTmpCClineE = "|" then 'have not gotten geiop by other means 
          If enableFreeGeoIP = True then SubmitGIP strdata 
        end if

        if isIPaddress(strdata) and strTmpCNlineE = "|" and strTmpCClineE = "|" then 'have not gotten geiop by other means 		
			'MsgBox "enableIP_DB=" & enableIP_DB
			If enableIP_DB = True then 
				
				strTmpCClineE = "|" & DBIP_GeoLocate(strdata)'Returns Country Code
				MoveSSLocationEntries
			end if
		end if
		
        'Proofpoint ET Intelligence lookups
        if BoolUseETIntelligence = True then 
          PPointSubmit "ip"
          if boolCheckProofpointIDS = True then strPPidsLineE = CheckProofpIDS("ip", strdata)
        end if 
        
      elseif instr(strData,".") then
      
        if instr(strData,"/") then
          'URL
          strDomainFromURL = strData
          if instr(lcase(strDomainFromURL),"http://") then strDomainFromURL = replace(lcase(strDomainFromURL),"http://","")
          if instr(lcase(strDomainFromURL),"https://") then strDomainFromURL = replace(lcase(strDomainFromURL),"https://","")
          if instr(strDomainFromURL,"/") then 
            strTmpDomainFromURL = left(strDomainFromURL,instr(strDomainFromURL,"/"))
          else
             strTmpDomainFromURL = strDomainFromURL
          end if
          if not DicScannedItems.Exists(strTmpDomainFromURL) then
            if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Have not scanned domain " & strTmpDomainFromURL,BoolEchoLog 
            if not DicPendingItems.Exists(strTmpDomainFromURL) then
              if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Adding domain address to pending items " & strTmpDomainFromURL ,BoolEchoLog 
              DicPendingItems.Add strTmpDomainFromURL, DicPendingItems.Count 
              boolPendingItems = True
            end if
          end if
        else'domain lookup
			strOptionalParameter = ""
            strVT_APIurl = "http://www.virustotal.com/vtapi/v2/domain/report?"  
            BoolPost = false
            strDataType = "domain="
			if boolUseTrancoList = True then
			
				if boolTrancoSQL = True then 
					sSQL = "select T_Score from Tranco where T_Domain = ? " 
					strTrancoLineE = "|" & ReturnSQLiteItem(sSQL, strScanDataInfo, "T_Score")
					if strTrancoLineE <> "|" and boolSkipOnTrancoHit = True and BoolDisableVTlookup = False then
						boolSkipDomain = True
						strTmpVTTIlineE = strScanDataInfo & "|||||" 'set VTTL entries to be blank since we skipping the lookups
					end if
				elseif dictTrancoList.exists(strScanDataInfo) Then
					strTrancoLineE = "|" & dictTrancoList.item(strScanDataInfo)
					if boolSkipOnTrancoHit = True and BoolDisableVTlookup = False then
						boolSkipDomain = True
						if BoolDisableVTlookup = False then strTmpVTTIlineE = strScanDataInfo & "|||||" 'set VTTL entries to be blank since we skipping the lookups
					end if
				else
					strTrancoLineE = "|"
					boolSkipDomain = False
				end if
			end if
		  if boolsubmitVT = True and boolSkipDomain = False then 
            VT_Submit
            inLoopCounter = inLoopCounter + 1
            If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
          end if
		  if boolUseQuad9 = True then
			 strQuad9DNS = nslookup_Return(strScanDataInfo & " " & "9.9.9.9")
			if strQuad9DNS = "" then
				strQuad9DNS = "|nxdomain"
			else
				strQuad9DNS = "|"
			end if
		  end if
		  If boolUseAlienVault = True then 'process domain
				strAlienVaultReturn = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/domain/", strData, "/general")
				if BoolDebugTrace = True then  logdata strDomainreportsPath & "\AVault_Domain_" & strData & ".txt", strData & vbtab & strAlienVaultReturn,BoolEchoLog 
				KeywordSearch strAlienVaultReturn 'keyword search watch list processing
				if boolAlienVaultNIDS = True and strAlienVaultkey <> "" and instr(strAlienVaultReturn, chr(34) & "nids_list" & chr(34)) > 0 then ProcessAlienVaultNIDS "https://otx.alienvault.com/api/v1/indicators/domain/", strScanDataInfo
				if boolAlienHostCheck = True and instr(strAlienVaultReturn, chr(34) & "url_list" & chr(34)) > 0 then
				
					if dictURLWatchList.count > 0 or boolLogURLs = True then
						strAlienHostURLs = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/domain/", strScanDataInfo, "/url_list")
						ProcessAlienURLs strAlienHostURLs
					end if
				end if
		  end if
		  AlienVaultPulseLine = AlienPulse(strAlienVaultReturn)
		  AlienVaultValidation = AlienValidation(strAlienVaultReturn)
		  
		If BoolSeclytics = True Then 'set to true to use Seclytics
			SeclytReturnBody = httpget("https://api.seclytics.com/hosts/", strScanDataInfo,"?","access_token", SeclyApikey, false) 'get API results
			SeclyticsProcess(SeclytReturnBody) 'process API results populating dictionaries
			SeclytRepReason = dict2List(DicIP_Context, "^") 'create list from dict
			if len(SeclytRepReason) > 32767 then SeclytRepReason = truncateCell(SeclytRepReason)
			SeclytFileRep = dict2List(DicFile_Context, "^")
			SeclytFileCount = getSeclyticFileCount(SeclytReturnBody)'get file count from number of hashes
			KeywordSearch SeclytReturnBody 'keyword search watch list processing
			SeclytWhitelist SeclytReturnBody 'Set validation if whitelisted
			If strTmpIPlineE = "|" Or strTmpIPlineE = "" Then
				SeclytPdns SeclytReturnBody
				domainPassiveDNS strTmpIPlineE 'set strRevDNS and pending items
			End If	
		End If
		  
        end If 'end domain lookup  
		  
     end If 'end instr(strData,".") then
      'end if

      'if an IP address then this will be blank
      if strDomainListOut = "" then strDomainListOut = "|"
      'if a domain then this will be blank
      if strTmpTGlineE = "" and BoolUseThreatGRID = True then  
        strTmpTGlineE ="|"
      elseif BoolUseThreatGRID = False then
        strTmpTGlineE =""
      end if
      
	  if intVTListDataType = 1 then' 0=unknown, 1 domain/IP, 2=hash, 3=hash/domain/ip
		if enableZEN = True then strTmpZENlineE = addpipe(strTmpZENlineE)
		
		  strTmpCNlineE = addpipe(strTmpCNlineE)
		  strTmpCClineE = addpipe(strTmpCClineE)
		  strTmpRNlineE =  addpipe(strTmpRNlineE)
		  strTmpRClineE = addpipe(strTmpRClineE)
		  strTmpCITlineE = addpipe(strTmpCITlineE)
		  strTmpIPlineE = addpipe(strTmpIPlineE)
		  if EnableCBL = True then strTmpCBLlineE = addpipe(strTmpCBLlineE)
		  if boolEnableZDBL = True and strTmpZDBLlineE = "" then strTmpZDBLlineE = addpipe(strTmpZDBLlineE)
		  if EnableBarracuda = True then strTmpCudalineE = addpipe(strTmpCudalineE)
		  if enableURIBL = True then strTmpURIBLlineE = addpipe(strTmpURIBLlineE)
		  if enableSURBL = True then strTmpSURbLineE = addpipe(strTmpSURbLineE)
		  if enableSORBS = True then strSORBSlineE  = addpipe(strSORBSlineE)
		  if strDDNSLineE = "" then strDDNSLineE = "|"
		  if boolUseQuad9 = True then strQuad9DNS = addpipe(strQuad9DNS)
		  if boolAlienVaultNIDS = True then 
			AlienNIDS = addpipe(AlienNIDS)
			AlienNIDScount = addpipe(AlienNIDScount)
			'Add deduplicated categories
			for each strTmpCategory in dictNIDStmpCategory
				if AlienNIDSCat = "" then
					AlienNIDSCat = strTmpCategory
				else
					AlienNIDSCat = AlienNIDSCat & "^" & strTmpCategory
				end if
			next
			AlienNIDSCat = addpipe(AlienNIDSCat)
			dictNIDStmpCategory.RemoveAll
		  end if
	  end if
		'format Date time the same for easier sorting
		strTmpCreationD = replace(strTmpWCO_CClineE, "|", "")
		if isdate(strTmpCreationD) then
			strTmpCreationD = GetFormattedDate(strTmpCreationD) & " " & FormatDateTime(strTmpCreationD,4)
			strTmpWCO_CClineE = "|" & strTmpCreationD
		end if

      if strRevDNS = "" then  strRevDNS = "|"
      strTmpIPContactLineE = addPipe(strTmpIPContactLineE)
      strDomainListOut = addpipe(strDomainListOut)
      
	  if boolUseTrancoList = True then strTrancoLineE = addPipe(strTrancoLineE)
      if boolUseThreatCrowd = True and strTMPTCrowdLine = "" then strTMPTCrowdLine = "|"
      if strTmpVTPositvLineE = "" and BoolDisableVTlookup = False then strTmpVTPositvLineE = "||||"
      if intHashDetectionsLineE = "" then intHashDetectionsLineE = "|"
      If BoolCheckTrendMicro = True then strTrendMicroLineE = addpipe(strTrendMicroLineE)
      If boolCheckMicrosoft = True then strMicrosoftLineE = addpipe(strMicrosoftLineE)
      If boolCHeckMcAfee = True then strMcAfeeLineE = addpipe(strMcAfeeLineE)
      If boolCheckSophos = True then strSophoslineE = addpipe(strSophoslineE)
      If boolCheckSymantec = true then strSymanteclineE = addPipe(strSymanteclineE)
      If boolCheckESET = True then strESETlineE = addpipe(strESETlineE)
      If boolCheckAvira = True then strAviralineE = addPipe(strAviralineE)
      If boolCheckDrWeb = True then strDrWeblineE = addPipe(strDrWeblineE)
	  if boolCheckFSecure = True then strFSecurelineE = addPipe(strFSecurelineE)
	  if boolCheckPanda = True then strPandalineE = addPipe(strPandalineE)
	  if boolCheckBitdefender = True then strBitdefenderlineE = addPipe(strBitdefenderlineE)
	  if DisplayVendor <> ""  then strDiplayVendDname = addPipe(strDiplayVendDname)
	  if boolUseAlienVault = True then AlienVaultPulseLine = addPipe(AlienVaultPulseLine)
	  if boolUseAlienVault = True Or BoolSeclytics = True then AlienVaultValidation = addPipe(AlienVaultValidation)
	  If (boolUseAlienVault = True Or BoolSeclytics = True) and dictKWordWatchList.count > 0 then strTmpKeyWordWatchList = addPipe(strTmpKeyWordWatchList)
      if strDetectNameLineE = "" then strDetectNameLineE = "|"
      strTmpDomainRestric = AddPipe(strTmpDomainRestric)
      if strTmpCacheLineE = "" then strTmpCacheLineE = "|"
      if strTmpMalShareLineE = "" and BoolEnableMalshare = True then strTmpMalShareLineE = "|"


      if intHashDetectionsLineE <> "|" then'hash lookups
        'malware scoring
         if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", intHashDetectionsLineE & "|initial score|" & intTmpMalScore & "|" & IntTmpGenericScore & "|" & IntTmpPUA_Score & "|" & IntTmpHkTlScore & "|" & IntTmpAdjustedMalScore, false
        IntTmpAdjustedMalScore = intTmpMalScore

        if ispipeorempty(strTrendMicroLineE)  = False then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if ispipeorempty(strMicrosoftLineE)  = False then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if ispipeorempty(strMcAfeeLineE) = False then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if ispipeorempty(strSophoslineE)  = False then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strSymanteclineE   <> "|" and boolCheckSymantec = True then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strESETlineE   <> "|" then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strAviralineE   <> "|" and boolCheckAvira = true then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strDrWeblineE   <> "|" and boolCheckDrWeb = True then _
         IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strFSecurelineE <> "|" and boolCheckFSecure = True then _
		 IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strBitdefenderlineE <> "|" and boolCheckBitdefender = True then _
		 IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5
        if strPandalineE <> "|" and boolCheckPanda = True then _
		 IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 5		 
        if ispipeorempty(strTmpTGlineE) = False then
          if intTmpMalScore > 1 and IntTmpPUA_Score < 1 then _
           IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 1
        end if

        if isnumeric(strTmpMSOlineE) then
           if strTmpMSOlineE > 2 then
            if intTmpMalScore > 1 and IntTmpPUA_Score < 1 then _
             IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 1      
           end if

        end if
   
        if ispipeorempty(strTMPTCrowdLine) = False then
          if intTmpMalScore > 1 and IntTmpPUA_Score < 1 then _
           IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 1
        end if      
        
        'lower adjusted mal score due to pua detections
        if IntTmpPUA_Score > 30 then 
          IntTmpAdjustedMalScore = 0
        elseif IntTmpPUA_Score > IntTmpAdjustedMalScore + 15 then 
          if IntTmpGenericScore - intTmpMalScore > 2 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore - 10
          else
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -8
          end if
        elseif IntTmpPUA_Score > IntTmpAdjustedMalScore + 10 then 
          if IntTmpGenericScore - intTmpMalScore > 2 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore - 7
          else
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -5
          end if
        elseif IntTmpPUA_Score > IntTmpAdjustedMalScore + 3 then 
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -2
        end if  
        if IntTmpAdjustedMalScore < 0 then IntTmpAdjustedMalScore = 0
        
        ' adjusted mal score added to for generic detections
        if IntTmpPUA_Score < 1 and IntTmpGenericScore > 0 and intTmpMalScore > 15 then 
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/2)  
        elseif IntTmpGenericScore > 10 and intTmpMalScore > 10 then 
          if IntTmpPUA_Score < 1 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/2)  
          elseif IntTmpPUA_Score < 10 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/3)  
          end if
        elseif IntTmpPUA_Score < 1 and IntTmpGenericScore > 15 and intTmpMalScore > 8 then 
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/2) 
        elseif IntTmpPUA_Score < 2 and IntTmpGenericScore > 15 and intTmpMalScore > 15 then 
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/2)    
        elseif IntTmpPUA_Score < 2 and IntTmpGenericScore > 14 and intTmpMalScore > 19 then 
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + round(IntTmpGenericScore/2)                        
        end if
        
        'adjust mal score from last scan date
        if isdate(strDateTimeLineE) and IntTmpAdjustedMalScore < 12 then   
          'adjusted mal score decrease on last scan  
          if DateDiff("d", cdate(strDateTimeLineE),now ) > 180 then
            if IntTmpAdjustedMalScore < 6 then 
              IntTmpAdjustedMalScore = 0
            elseif IntTmpAdjustedMalScore < 12 then 
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -5
            end if  
          elseif DateDiff("d", cdate(strDateTimeLineE),now ) > 90 then
            if IntTmpAdjustedMalScore < 3 then 
              IntTmpAdjustedMalScore = 0
            elseif IntTmpAdjustedMalScore < 6 then 
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -2
            elseif IntTmpAdjustedMalScore < 11 then 
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -1
            end if          
          elseif DateDiff("d", cdate(strDateTimeLineE),now ) > 60 then
            if IntTmpAdjustedMalScore < 2 then 
              IntTmpAdjustedMalScore = 0
            elseif IntTmpAdjustedMalScore < 5 then 
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -2
            elseif IntTmpAdjustedMalScore < 10 then 
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore -1
            end if           
          end if
        'adjusted mal score increase on last scan  
        elseif isdate(strDateTimeLineE) and IntTmpAdjustedMalScore > 32 then
            if DateDiff("d", cdate(strDateTimeLineE),now ) < 4 then
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +5
            end if
        elseif isdate(strDateTimeLineE) and IntTmpAdjustedMalScore > 22 then
            if DateDiff("d", cdate(strDateTimeLineE),now ) < 4 then
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +3
            end if
        elseif isdate(strDateTimeLineE) and IntTmpAdjustedMalScore > 11 then
            if DateDiff("d", cdate(strDateTimeLineE),now ) < 4 then
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +1
            end if          
        end if
        
        'increase adjusted mal score with hacker tool detections
        if IntTmpHkTlScore > 0 then
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + IntTmpHkTlScore
        end if
        
        'bump up adjusted mal score if PUA is 0 and already has a decent score
        if IntTmpPUA_Score < 1 and IntTmpAdjustedMalScore > 25 then
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +5
        elseif IntTmpPUA_Score < 1 and IntTmpAdjustedMalScore > 20 then
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +3
        elseif IntTmpPUA_Score < 1 and IntTmpAdjustedMalScore > 15 then
          IntTmpAdjustedMalScore = IntTmpAdjustedMalScore +1 
        end if
        
        'add detection category name if no specific name provided
        if (StrDetectionTypeLineE = "|" or StrDetectionTypeLineE = "") or MalwareKeyWordNames(StrDetectionTypeLineE) <> "" or MalwareKeyWordScore(StrDetectionTypeLineE) <> 0 then
          if int(IntTmpPUA_Score) > 30 and int(IntTmpPUA_Score) > int(IntTmpAdjustedMalScore) Then
            StrDetectionTypeLineE = "|pua/pup"
          elseif int(IntTmpPUA_Score) > 10 and 3 > int(IntTmpAdjustedMalScore) Then
            StrDetectionTypeLineE = "|pua/pup"
          elseif int(IntTmpPUA_Score) > 7 and 1 > int(IntTmpAdjustedMalScore) and len(StrDetectionTypeLineE) > 1 then
            if DictPUANames.exists(right(StrDetectionTypeLineE,len(StrDetectionTypeLineE)-1)) Then _
            StrDetectionTypeLineE = "|pua/pup"          
          end if
        end if
        if (StrDetectionTypeLineE = "|" or StrDetectionTypeLineE = "") and len(strDetectNameLineE) > 1 then
          if DictPUANames.exists(right(strDetectNameLineE,len(strDetectNameLineE)-1)) then
            if IntTmpPUA_Score > IntTmpHkTlScore Then
              if DicthktlNames.exists(right(strDetectNameLineE,len(strDetectNameLineE)-1)) = False then
                StrDetectionTypeLineE = "|pua/pup"
              else
                StrDetectionTypeLineE = "|grayware"
              end if
            else
              StrDetectionTypeLineE = "|grayware"
            end if
          end if
        end if
        'whitelist detections can put things into negative so zero out
        if IntTmpGenericScore < 0 then IntTmpGenericScore = 0
        if intTmpMalScore < 0 then intTmpMalScore = 0
      end if
      
     
      if StrDetectionTypeLineE = "" then StrDetectionTypeLineE = "|"
      
      strTmpSigAssesslineE = ""
      'record digital signatures
      if strCBdigSig <> "|" and strCBdigSig <> "" and strCBdigSig <> "n/a" Then
        if DictWhiteDSigNames.exists(strCBdigSig) then
          strTmpSigAssesslineE = "|Known Publisher"
          if IntTmpAdjustedMalScore > 1 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore - 2
          elseif IntTmpAdjustedMalScore > 0 then
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore - 1
          end if
        elseif StrDetectionTypeLineE = "trojan" then
          if DictMalDSigNames.exists(strCBdigSig) = False then
            DictMalDSigNames.add strCBdigSig, IntTmpAdjustedMalScore
            strTmpSigAssesslineE = "|New Malware Signer"
            LogData strCachePath & "\ds_mal.dat", strCBdigSig & "|" & IntTmpAdjustedMalScore, false
          end if
        elseif StrDetectionTypeLineE = "pua/pup" Then
          if DictPUADSigNames.exists(strCBdigSig) = False then
            DictPUADSigNames.add strCBdigSig, IntTmpPUA_Score
            strTmpSigAssesslineE = "|New PUA/PUP Signer"
            LogData strCachePath & "\ds_pup.dat", strCBdigSig & "|" & IntTmpPUA_Score, false
          end if
        elseif len(StrDetectionTypeLineE) > 2 then 'grayware
          if DictGrayDSigNames.exists(strCBdigSig) = False and DictPUADSigNames.exists(strCBdigSig) = False then
            DictGrayDSigNames.add strCBdigSig, intTmpMalScore & "^" & IntTmpGenericScore & "^" & IntTmpPUA_Score & "^" & IntTmpHkTlScore & "^" & IntTmpAdjustedMalScore 
            strTmpSigAssesslineE = "|New Grayware Signer"
            LogData strCachePath & "\ds_gry.dat", strCBdigSig & "|" & intTmpMalScore & "^" & IntTmpGenericScore & "^" & IntTmpPUA_Score & "^" & IntTmpHkTlScore & "^" & IntTmpAdjustedMalScore , false
          end if
        end if
        if strTmpSigAssesslineE = "" then 
          if DictMalDSigNames.exists(strCBdigSig) = True then
            strTmpSigAssesslineE = "|Previous Malware Signer"
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + DictMalDSigNames.item(strCBdigSig)
          elseif DictPUADSigNames.exists(strCBdigSig) = True then
            strTmpSigAssesslineE = "|Previous PUA/PUP Signer"
            if isnumeric(DictPUADSigNames.item(strCBdigSig)) then
              IntTmpPUA_Score = IntTmpPUA_Score + DictPUADSigNames.item(strCBdigSig)
            else
              IntTmpPUA_Score = IntTmpPUA_Score + left(DictPUADSigNames.item(strCBdigSig), instr(DictPUADSigNames.item(strCBdigSig), "^") -1)
            end if
          elseif DictGrayDSigNames.exists(strCBdigSig) = True then
            strTmpSigAssesslineE = "|Previous Grayware Signer"

          elseif DictDSigNames.exists(strCBdigSig) = False then 'sig bucket
            DictDSigNames.add strCBdigSig, 1
            strTmpSigAssesslineE = "|New Signer"
            if BoolUsePassiveTotal = True then 
              CheckPassiveTotal "whois", strCBdigSig
              if strPassiveTotal = "" then
                'CheckPassiveTotal "cert", strCBdigSig 'PassiveTotal doesn't appear to parse the field properly in their dataset for this query to work and has been reported to them for a fix.
              end if
            end if
          else
            strTmpSigAssesslineE = "|Previously Identified Signer"
            if strCBprevalence > 0 then
              DictDSigNames.item(strCBdigSig) = clng(DictDSigNames.item(strCBdigSig)) + clng(strCBprevalence)
            else
              DictDSigNames.item(strCBdigSig) = clng(DictDSigNames.item(strCBdigSig)) + 1
            end if
          end if
        end if
      end if

      if strDFSlineE = "" then 
        if strDateTimeLineE <> "" then 
          strDFSlineE = "|" & strDateTimeLineE
        else  
          strDFSlineE = "|" & Date & " " & Time
        end if
      else
        strDFSlineE = addpipe(strDFSlineE)
      end if
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", intHashDetectionsLineE & "|adjusted score|" & intTmpMalScore & "|" & IntTmpGenericScore & "|" & IntTmpPUA_Score & "|" & IntTmpHkTlScore & "|" & IntTmpAdjustedMalScore, false
      
      
      
      if boolEnableMetascan = True then strTmpMSOlineE = AddPipe(strTmpMSOlineE) 'add a | if one does not exist
      if BoolUseCIF = true then strTmpCIFlineE = AddPipe(strTmpCIFlineE)
      if boolEnablePassiveTotal = True then strPassiveTotal = AddPipe(strPassiveTotal)
      strTmpWCO_CClineE = AddPipe(strTmpWCO_CClineE)

      strTmpSinkHole = AddPipe(strTmpSinkHole)
      if BoolSigCheckLookup = True or BoolUseCarbonBlack = True then
        strCBfilePath = AddPipe(strCBfilePath) 'CB File Path
		if BoolSigCheckLookup = True then
			'crowdstrike doesn't include any of these so make sure the column was provided
			if intPublisherLoc > -1 then 
				strCBdigSig = AddPipe(strCBdigSig) 'CB Digital Sig
				if strTmpSigAssesslineE = "" then strTmpSigAssesslineE = "|"
			end if
			if intCompanyLoc > -1 then strCBcompanyName = AddPipe(strCBcompanyName)'CB Company Name
			if inthfProductLoc > -1 then strCBproductName = AddPipe(strCBproductName) 'Product Name  
			
		else 'BoolUseCarbonBlack = True
			strCBdigSig = AddPipe(strCBdigSig) 'CB Digital Sig
			strCBcompanyName = AddPipe(strCBcompanyName)'CB Company Name
			strCBproductName = AddPipe(strCBproductName) 'Product Name  
			if strTmpSigAssesslineE = "" then strTmpSigAssesslineE = "|"
		end if
        
      end if
      if boolEnableCuckooV2 = True then
		strCBFileSize = AddPipe(strCBFileSize) 
		strFileTypeLineE = addpipe(strFileTypeLineE)		
	  end if
	  if boolEnableCuckoo = True Or (BoolDisableVTlookup = False and boolVTuseV3 = True) then
        strCBdigSig = AddPipe(strCBdigSig) 'CB Digital Sig
        strCBcompanyName = AddPipe(strCBcompanyName)'CB Company Name
        strCBproductName = AddPipe(strCBproductName) 'Product Name  
        strCBFileSize = AddPipe(strCBFileSize)  
        strPE_TimeStamp = AddPipe(strPE_TimeStamp)    
        strTmpSigAssesslineE = Addpipe(strTmpSigAssesslineE)
        strFileTypeLineE = addpipe(strFileTypeLineE)
     end if
     if BoolDisableVTlookup = False and boolVTuseV3 = True then
        strMimeTypeLineE = AddPipe(strMimeTypeLineE)
     End if
      If boolEnableCuckoo = True then    
        StrYARALineE = addpipe(StrYARALineE)
        if strDetectNameLineE = "None Identified" then 
          strDetectNameLineE = "|"
        else
          strDetectNameLineE = addpipe(strDetectNameLineE)
        end if
        if StrDetectionTypeLineE = "None Identified" then 
          StrDetectionTypeLineE = "|"
        else
          StrDetectionTypeLineE = addpipe(StrDetectionTypeLineE)
        end if
      end If
      
      if boolTGwasEnabled = True then 
        strTmpTGlineE = addpipe(strTmpTGlineE)
      end if
      if BoolUseETIntelligence = True then 
        strTmpPPointLine = AddPipe(strTmpPPointLine)
        if boolCheckProofpointIDS = True then strPPidsLineE = AddPipe(strPPidsLineE)
      end if
      strCategoryLineE = AddPipe(strCategoryLineE)   
        
      if boolEnableCuckoo = True then strCuckooScore  = AddPipe(strCuckooScore)

      if BoolEnCaseLookup = True or BoolUseCarbonBlack = True or (BoolDisableVTlookup = False and boolVTuseV3 = True) then
          strCBfilePath = AddPipe(strCBfilePath) 'CB File Path
          if inthfSizeLoc > -1 or (BoolDisableVTlookup = False and boolVTuseV3 = True) then strCBFileSize = AddPipe(strCBFileSize)  
      end if
      if BoolUseCarbonBlack = True then 'CB custom CSV export
        strCBprevalence = AddPipe(strCBprevalence)
		strCBFileSize = AddPipe(strCBFileSize) 'crowdstrike provides prevalence but not
	  elseif cint(inthfPrevalenceLoc) > -1 then 'CSV
		strCBprevalence = AddPipe(strCBprevalence)
        if BoolSigCheckLookup = True and inthfSizeLoc > -1 then strCBFileSize = AddPipe(strCBFileSize) 'crowdstrike provides prevalence but not file size.
      else
        strCBprevalence = ""
      end if
      if cint(intHostLocation) > 0 then
        strCBhosts = AddPipe(strCBhosts)
      else
        strCBhosts = ""
      end if
	  
	  if boolCheckProofpointIDS = True then strPPidsLineE = AddPipe(strPPidsLineE)
	  
	  'Add columns for detection name array if none exist
	  if cint(intDetectionNameCount) > 0 and intVTListDataType = 1 then ' 0=unknown, 1 domain/IP, 2=hash, 3=hash/domain/ip
		  if len(DetectionNameSSlineE) < 1 + ubound(ArrayDnameLineE) and BoolDisableVTlookup = False then 
			do while len(DetectionNameSSlineE) < 1 + ubound(ArrayDnameLineE)
				DetectionNameSSlineE = DetectionNameSSlineE & "|"
			loop
		  end If
	  end If
	  if dictDnameWatchList.count > 0 And (BoolSeclytics = True Or intVTListDataType = 2) then strDnameWatchLineE = addPipe(strDnameWatchLineE)
	  
	  If BoolSeclytics = True Then 'set to true to use Seclytics
		SeclytRepReason = AddPipe(SeclytRepReason) 'Seclytics Reputation and Reason
		SeclytFileRep = AddPipe(SeclytFileRep)'Seclytics Associated File Metadata
		SeclytFileCount = AddPipe(SeclytFileCount)'Seclytics File Count"
	  End if 
	  If BoolSeclytics = True Or intVTListDataType = 1 Then
		if dictURLWatchList.count > 0 then strURLWatchLineE = addPipe(strURLWatchLineE)
		if dictIPdomainWatchList.count > 0 then strIpDwatchLineE = addPipe(strIpDwatchLineE)
	  End If
	  If boolPulsedive = True Then
	  	strTmpPulsediveLineE = AddPipe(strTmpPulsediveLineE)
	  	sslOrg = AddPipe(sslOrg)
	  	sslSubject = AddPipe(sslSubject)
	  End if  				
      'write spreadsheet row
      select case intVTListDataType
        case 1
          'write row for domain & IP
          strTmpSSline = strTmpSSline  & strTmpVTTIlineE & strTrancoLineE & strTmpPPointLine & strSORBSlineE & strQuad9DNS & strTmpCBLlineE & strTmpCudalineE & strTmpZENlineE & strTmpZDBLlineE & strTmpURIBLlineE & strTmpSURbLineE & strTmpTGlineE & strTmpCIFlineE & strTmpMSOlineE & strTmpCNlineE & strTmpCClineE & strTmpRNlineE & strTmpRClineE & strTmpCITlineE & strTmpWCO_CClineE & strRevDNS & strTmpIPContactLineE & strDomainListOut & strTmpIPlineE & strCategoryLineE & strDDNSLineE & strTMPTCrowdLine & AlienVaultPulseLine & AlienVaultValidation & strTmpKeyWordWatchList & strTmpVTPositvLineE & strTmpDomainRestric & strTmpSinkHole & strTmpCacheLineE & DetectionNameSSlineE & strIpDwatchLineE & strDnameWatchLineE & strURLWatchLineE & strPPidsLineE & AlienNIDScount & AlienNIDSCat & AlienNIDS & SeclytRepReason & SeclytFileRep & SeclytFileCount & strTmpPulsediveLineE & sslSubject & sslOrg '& strTmpCacheLineE
        case 2
          If dictDnameWatchList.count > 0 then strDnameWatchLineE = addPipe(strDnameWatchLineE)
		  'Add to adjusted malware score for custom list malware and update detection name if one was given in malhash.dat
          if DictMalHash.exists(lcase(strdata)) then 
            IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + 100
            if DictMalHash.item(lcase(strdata)) <> "" and strDetectNameLineE = "|" then strDetectNameLineE = "|" & DictMalHash.item(lcase(strdata))
          end if
          if Dictwhitehash.exists(lcase(strdata)) then 
            if IntTmpAdjustedMalScore < 5 then
              IntTmpAdjustedMalScore = 0
            else
              IntTmpAdjustedMalScore = IntTmpAdjustedMalScore - 5
            end if
            if Dictwhitehash.item(lcase(strdata)) <> "" and strDetectNameLineE = "|" then strDetectNameLineE = "|" & Dictwhitehash.item(lcase(strdata))
          end if
          if boolDisableSQL_IQ = False and boolSQLcache = True and ishash(strdata) = True then SQL_Intelligence_Query lcase(strdata)           
          'write row for hash lookups
          strTmpSSline = strTmpSSline  & intHashDetectionsLineE & "|" & intTmpMalScore & "|" & IntTmpGenericScore & "|" & IntTmpPUA_Score & "|" & IntTmpHkTlScore & "|" & IntTmpAdjustedMalScore & strTmpMSOlineE & strTmpPPointLine & strTmpTGlineE & strTMPTCrowdLine & strTrendMicroLineE & strMicrosoftLineE & strMcAfeeLineE & strSophoslineE & strSymanteclineE & strESETlineE & strAviralineE & strDrWeblineE & strPandaLineE & strFSecurelineE & strBitdefenderLineE & strDiplayVendDname & AlienVaultPulseLine & "|" & strDateTimeLineE & strDetectNameLineE & StrDetectionTypeLineE & strTmpCacheLineE & strDnameWatchLineE & strTmpMalShareLineE & strCBfilePath & strCBdigSig & strCBcompanyName & strCBproductName & strCBprevalence & strCBFileSize & strTmpSigAssesslineE & strCuckooScore & strCBhosts & strPassiveTotal & strDFSlineE & StrYARALineE & strMimeTypeLineE & strFileTypeLineE & strPE_TimeStamp & strPPidsLineE & SeclytFileRep & strIpDwatchLineE & strURLWatchLineE & strTmpKeyWordWatchList
      end select 
      

      
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSSline = "  & strTmpSSline,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSSline = "  & intHashDetectionsLineE & "-" & "|" & intTmpMalScorE & "-" & "|" & IntTmpGenericScorE & "-" & "|" & IntTmpPUA_ScorE & "-" & "|" & IntTmpHkTlScorE & "-" & "|" & IntTmpAdjustedMalScorE & "-" & strTmpMSOlineE & "-" & strTmpTGlineE & "-" & strTMPTCrowdLinE & "-" & strTrendMicroLineE & "-" & strMicrosoftLineE & "-" & strMcAfeeLineE & "-" & strSophoslineE & "-" & strSymanteclineE & "-" & strESETlineE & "-" & strAviralineE & "-" & strDrWeblineE & "-" & "|" & strDateTimeLineE & "-" & strDetectNameLineE & "-" & StrDetectionTypeLineE & "-" & strTmpCacheLineE & "-" & strTmpMalShareLineE,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSSline" & "=" & strTmpSSline ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "intHashDetectionsLineE" & "=" & intHashDetectionsLineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpVTTIlineE" & "=" & strTmpVTTIlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpPPointLine" & "=" & strTmpPPointLine ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCBLlineE" & "=" & strTmpCBLlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCudalineE" & "=" & strTmpCudalineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpZENlineE" & "=" & strTmpZENlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpZDBLlineE" & "=" & strTmpZDBLlineE ,BoolEchoLog   
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpURIBLlineE" & "=" & strTmpURIBLlineE ,BoolEchoLog   
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSURbLineE" & "=" & strTmpSURbLineE ,BoolEchoLog   
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strSORBSlineE" & "=" & strSORBSlineE ,BoolEchoLog   
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpTGlineE" & "=" & strTmpTGlineE ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpZDBLlineE" & "=" & strTmpZDBLlineE ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCIFlineE" & "=" & strTmpCIFlineE ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpMSOlineE" & "=" & strTmpMSOlineE ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCNlineE" & "=" & strTmpCNlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCClineE" & "=" & strTmpCClineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpRNlineE" & "=" & strTmpRNlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpRClineE" & "=" & strTmpRClineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCITlineE" & "=" & strTmpCITlineE ,BoolEchoLog
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strRevDNS" & "=" & strRevDNS ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpIPContactLineE" & "=" & strTmpIPContactLineE ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strDomainListOut" & "=" & strDomainListOut ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "AlienVaultPulseLine" & "=" & AlienVaultPulseLine ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "AlienVaultValidation" & "=" & AlienVaultValidation ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpKeyWordWatchList" & "=" & strTmpKeyWordWatchList ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpVTPositvLineE" & "=" & strTmpVTPositvLineE ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpIPlineE" & "=" & strTmpIPlineE ,BoolEchoLog                    
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpDomainRestric" & "=" & strTmpDomainRestric ,BoolEchoLog                    
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSinkHole" & "=" & strTmpSinkHole ,BoolEchoLog                    
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpCacheLineE" & "=" & strTmpCacheLineE ,BoolEchoLog                    
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpMalShareLineE" & "=" & strTmpMalShareLineE ,BoolEchoLog    
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTMPTCrowdLine" & "=" & strTMPTCrowdLine ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strDFSlineE " & "=" & strDFSlineE  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBFileSize " & "=" & strCBFileSize  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpSigAssesslineE " & "=" & strTmpSigAssesslineE  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCuckooScore " & "=" & strCuckooScore  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBhosts " & "=" & strCBhosts  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strPassiveTotal " & "=" & strPassiveTotal  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strDetectNameLineE " & "=" & strDetectNameLineE  ,BoolEchoLog 
       if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "StrDetectionTypeLineE " & "=" & StrDetectionTypeLineE  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "StrYARALineE " & "=" & StrYARALineE  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strFileTypeLineE " & "=" & strFileTypeLineE  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBprevalence " & "=" & strCBprevalence  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBfilePath " & "=" & strCBfilePath  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBcompanyName " & "=" & strCBcompanyName  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBproductName " & "=" & strCBproductName  ,BoolEchoLog 
	   if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strCBdigSig " & "=" & strCBdigSig  ,BoolEchoLog 
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTrendMicroLineE " & "=" & strTrendMicroLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strMicrosoftLineE " & "=" & strMicrosoftLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strMcAfeeLineE " & "=" & strMcAfeeLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strSophoslineE " & "=" & strSophoslineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strSymanteclineE " & "=" & strSymanteclineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strESETlineE " & "=" & strESETlineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strAviralineE " & "=" & strAviralineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strDrWeblineE " & "=" & strDrWeblineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strFSecurelineE " & "=" & strFSecurelineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strPandalineE " & "=" & strPandalineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTmpWCO_CClineE " & "=" & strTmpWCO_CClineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "DetectionNameSSlineE " & "=" & DetectionNameSSlineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strIpDwatchLineE " & "=" & strIpDwatchLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strDnameWatchLineE " & "=" & strDnameWatchLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strURLWatchLineE " & "=" & strURLWatchLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strPPidsLineE " & "=" & strPPidsLineE  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "AlienNIDScount " & "=" & AlienNIDScount  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "AlienNIDS " & "=" & AlienNIDS  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_SS_Debug" & "" & ".txt", "strTrancoLineE " & "=" & strTrancoLineE  ,BoolEchoLog 
	  
	  'Reset adjusted malware score
      IntTmpAdjustedMalScore = "0"
      'clear geoip
      strTmpCNlineE = "|"
      strTmpCClineE = "|"
      strTmpRNlineE = "|"
      strTmpRClineE = "|"
      strTmpCITlineE = "|"
      strTmpWCO_CClineE = "|"
      'clear domain list
      strDomainListOut = ""
      'clear IP lookup items
      strTmpTGlineE = "|"
      strTmpCBLlineE = ""
      strTmpCudalineE = ""
      strTmpZENlineE = ""
	  strCBL = ""
	  strTmpURIBLlineE = ""
	  strTmpSURbLineE = ""
	  strSORBSlineE = ""
	  strTmpIPlineE = "|"
      'clear domain lookup items
      strTmpZDBLlineE = ""
      
      'clear more stuff
      if boolUseTrancoList = True Then strTrancoLineE = "|"
      if boolUseThreatCrowd = True then strTMPTCrowdLine = "|"
      if BoolDisableVTlookup = False then strTmpVTPositvLineE = "||||"
      strTmpIPContactLineE = "|"    
      intHashDetectionsLineE = "|"
	  AlienVaultPulseLine = ""
	  AlienVaultValidation = ""
	  strTmpKeyWordWatchList = ""
	  AlienNIDScount = ""
	  AlienNIDS = ""
	  AlienNIDSCat = ""
      if boolEnableMetascan = True then strTmpMSOlineE = "|"
      if BoolUseETIntelligence = True then 
        strTmpPPointLine = "|"
        if boolCheckProofpointIDS = True then strPPidsLineE = "|"
      end if
	  if boolUseQuad9 = True then
		strQuad9DNS = "|"
	  end if
      intTmpMalScore = 0
      IntTmpPUA_Score = 0      
      IntTmpGenericScore = 0
      IntTmpHkTlScore = 0
      strTrendMicroLineE = ""
      strMicrosoftLineE = ""
      strMcAfeeLineE = ""
      strSophoslineE = ""
      strSymanteclineE = ""
      strESETlineE = ""
      strAviralineE = ""
      strDrWeblineE = ""      
	  strFSecurelineE = ""
	  strPandalineE = ""
	  strBitdefenderLineE = ""
	  strDiplayVendDname = ""
      strDateTimeLineE = ""
      strDetectNameLineE = "|"
      StrDetectionTypeLineE = "|"
      strTmpDomainRestric = "|"
      strTmpSinkHole = "|"
      strTmpCacheLineE = "|"
       strCBfilePath = "" 'CB File Path
       strCBdigSig = "" 'CB Digital Sig
       strCBcompanyName = "" 'CB Company Name
       strCBproductName = "" 'Product Name
       strFileMD5 = "" 'Temporary hash value
        strFileSHA256 = "" 'Temporary hash value
        strFileSHA1 = "" 'Temporary hash value
        strFileIMP = "" 'Temporary hash value
       strCBprevalence = 0
       strCBFileSize = ""
       strTmpSigAssesslineE = ""
       strCuckooScore = ""
       strPassiveTotal = ""
       strCategoryLineE = ""
       strRevDNS = ""
       strDFSlineE = ""
       strPE_TimeStamp = ""
       strFileTypeLineE = ""
       strMimeTypeLineE = ""
       strTmpPulsediveLineE = ""
       sslOrg = ""
       sslSubject = ""
       dictCountDomains.RemoveAll 'clear dict we use for tracking domain associations
	  
	  if boolNoCrLf = True then 
		strTmpSSline = replace(strTmpSSline,vbCr, "")
		strTmpSSline = replace(strTmpSSline,vbLf,"")
	  end if
	  'write output to spreadsheet/csv
	  if BoolCreateSpreadsheet = True and left(strTmpSSline,1) <> "|" then Write_Spreadsheet_line(strTmpSSline)
      strTmpSSline = ""
      StrYARALineE = ""
	  DetectionNameSSlineE = ""
	  strDnameWatchLineE = ""
	  strURLWatchLineE = ""
	  strIpDwatchLineE = ""
    'end if
loop  

For each item in DicScannedItems
  if strScannedItems = "" then 
    strScannedItems = item
  else
    strScannedItems = strScannedItems & vbcrlf & item
  end if  
next 


'parse domain to IP mapping
For Each Item In dicDomainIPmatch
  if strDomainIPmatch = "" then 
    strDomainIPmatch =  Item & vbtab & dicDomainIPmatch.Item(Item)
  else
    strDomainIPmatch = strDomainIPmatch & vbcrlf & Item & vbtab & dicDomainIPmatch.Item(Item)
  end if
next


'build string for this scan results
if strThisScanResults <> "" then strThisScanResults = "VirusTotal File Scan:" & vbcrlf & strThisScanResults & vbCrLf
if strWebScanResults <> "" and BoolReportWebScan = True then strThisScanResults = strThisScanResults & vbcrlf & "VirusTotal Web Scan:" & vbcrlf &  strWebScanResults & vbCrLf
if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug_TI" & "" & ".txt", "-----" & vbcrlf & "VirusTotal Threat Intelligence:" & vbcrlf & strTIScanResults & vbCrLf ,BoolEchoLog 
if strTIScanResults <> "" then strThisScanResults = strThisScanResults & vbcrlf & "VirusTotal Threat Intelligence:" & vbcrlf & strTIScanResults & vbCrLf
if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug_IP" & "" & ".txt", "-----" & vbcrlf & "VirusTotal IP Information:" & vbCrLf & strIPlinks & vbcrlf ,BoolEchoLog 
if strDomainIPmatch <> "" then strThisScanResults = strThisScanResults & vbcrlf & "Domain to IP Mapping:" & vbCrLf & strDomainIPmatch & vbcrlf & vbcrlf
if strIPlinks <> "" then strThisScanResults = strThisScanResults & vbcrlf & "VirusTotal IP Information:" & vbCrLf & strIPlinks & vbcrlf
if strDomainLinks <> "" then strThisScanResults = strThisScanResults & vbcrlf & "VirusTotal Domain Information:" & vbCrLf & strDomainLinks & vbcrlf
if StrRBL_Results <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "Listed RBLs:" & vbCrLf & StrRBL_Results & vbCrLf
if strThreatGRID_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "ThreatGRID:" & vbCrLf & strThreatGRID_Output & vbCrLf
if strDDNS_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "Dynamic DNS Domains:" & vbCrLf & strDDNS_Output & vbCrLf
if strXforce_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "IBM X-Force Exchange:" & vbCrLf & strXforce_Output & vbCrLf
if strTCrowd_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "Threat Crowd:" & vbCrLf & strTCrowd_Output & vbCrLf
if strPPoint_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "ET Intelligence:" & vbCrLf & strPPoint_Output & vbCrLf
if strSQL_Intelligence_Output <> "" then strThisScanResults = strThisScanResults & vbcrlf & vbcrlf & "Other Intelligence:" & vbCrLf & strSQL_Intelligence_Output & vbCrLf
if strCIFoutput <> "" then strThisScanResults = strThisScanResults & vbcrlf & strCIFoutput & vbCrLf
if StrIPMetaScanFormatted <> "" then strThisScanResults = strThisScanResults & vbcrlf & StrIPMetaScanFormatted


strThisScanResults = replace(strThisScanResults, vbcrlf & vbcrlf, vbcrlf)
LogOverwriteData strReportsPath & "\VT_Output" & "" & ".txt", strThisScanResults,BoolEchoLog 
if objFSO.fileexists(strCachePath & "\digsig.dat") then objFSO.deletefile(strCachePath & "\digsig.dat")
For each item in DictDSigNames
  LogData strCachePath & "\digsig.dat", item & "|" & DictDSigNames.item(item), false
next
if objFSO.fileexists(strCachePath & "\pathvend.dat") then objFSO.deletefile(strCachePath & "\pathvend.dat")
For each item in DictPathVendorStat
  LogData strCachePath & "\pathvend.dat", item & "|" & DictPathVendorStat.item(item), false
next

objFile.close
set objFile = nothing
wscript.sleep 10


if BoolAddStats = True then
  if BoolUseExcel = true then
    AddStatsExcel
  else
    AddStatsCSV
  end if
end if

wscript.sleep(30)
if objFSO.fileexists(CurrentDirectory & "\vtlist.que") = false then
  if BoolRunSilent = False Then
  	If objFSO.fileexists(strSSfilePath) = True Then 'if we output to a file then open it. Else Excel output was configured
     objShellComplete.run chr(34) & strSSfilePath & chr(34)
    End If 
  End if
  if BoolRunSilent = False then _
  Msgbox "The VTTL script has finished lookups and will exit. The following items were processed:" & vbcrlf & strScannedItems
else
  if objFSO.fileexists(CurrentDirectory & "\vtlist.txt") = true then objFSO.deletefile(CurrentDirectory & "\vtlist.txt")
  objFSO.movefile CurrentDirectory & "\vtlist.que", CurrentDirectory & "\vtlist.txt"
  if objFSO.fileexists(CurrentDirectory & "\sigcheck.que") = true then
    if objFSO.fileexists(CurrentDirectory & "\sigcheck.txt") = true then objFSO.deletefile(CurrentDirectory & "\sigcheck.txt")
    objFSO.movefile CurrentDirectory & "\sigcheck.que", CurrentDirectory & "\sigcheck.txt"
    objShellComplete.run "wscript.exe " & chr(34) & CurrentDirectory & "\" & wscript.ScriptName & Chr(34) & " " & strQueueParameters & " " & chr(34) & CurrentDirectory & "\sigcheck.txt" & Chr(34) 
  else
    objShellComplete.run "wscript.exe " & chr(34) & CurrentDirectory & "\" & wscript.ScriptName & Chr(34) & " " & strQueueParameters 
  end if
end if
  Set objShellComplete = Nothing 

 
Sub VT_Submit
Dim strtmpMetascanReslts
Dim arrayIPresults
Dim tmpCountURLs
Dim strTmpIPurl
Dim dicIPurls
Dim intCountDomains
Dim strTmpVTSips
Dim StrTmpDomainOrIP
Dim strNumberOfPositiveDetections
Dim strTmpRequestResponse
Dim DIcHashes
Dim DicHashReferrer
Dim DicHashComm
Dim DicHashDownloaded
Dim intPositiveDetectSection

If BoolDisableVTlookup = True Then 
	strTmpSSline = strScanDataInfo
	Exit Sub
End if
Set DIcHashes = CreateObject("Scripting.Dictionary")
Set DicHashReferrer = CreateObject("Scripting.Dictionary")
Set DicHashComm = CreateObject("Scripting.Dictionary")
Set DicHashDownloaded = CreateObject("Scripting.Dictionary")
Set dicIPurls = CreateObject("Scripting.Dictionary")
reDim arrayIPdomains(0)
Dim ArrayHostNames
Dim TmpCompareScore
Dim StrTmpMD5: StrTmpMD5 = ""
intVTpositiveDetections = 0
if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "VT Submit" ,BoolEchoLog
strtmpMetascanReslts = ""
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
strTmpVTSips = ""
strTmpRequestResponse = ""
strresponseText = ""
if boolVTuseV3 = True And ishash(strScanDataInfo) Then 'Only support v3 for hash lookups
	strFullAPIURL = strScanDataInfo
Else 'need to add support for v3 IP/domain lookups
	strFullAPIURL = strDataType & strScanDataInfo & strOptionalParameter & "&apikey=" & strAPIKey
end if

if BoolDisableVTlookup = False then
	lookupDelay
	if ishash(strScanDataInfo) and BoolDisableCacheLookup = False then
		strresponseText = CacheLookup("", "\vt\", strScanDataInfo, intHashCacheThreashold)
	end if

  if BoolPost = true and BoolReportOnly = False then
    'file url "https://www.virustotal.com/vtapi/v2/file/report"
    'url scan url "https://www.virustotal.com/vtapi/v2/url/scan"
    'url report "http://www.virustotal.com/vtapi/v2/url/report"


    if strresponseText <> "" then
		BoolSkipedVTlookup = True
		if sleepOnSkippedVT = True then strDateLookupTrack = Now 'set the date time when last lookup was performed for rate limit delay
	elseif strresponseText = "" then
		BoolSkipedVTlookup = False
      objHTTP.open "POST", strVT_APIurl, False
      objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"

        
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_HTTP_Debug" & "" & ".txt", "strFullAPIURL = " & strDataType & strScanDataInfo & strOptionalParameter, BoolEchoLog 
      on error resume next
      objHTTP.send strFullAPIURL
	  strDateLookupTrack = Now 'set the date time when last lookup was performed for rate limit delay
      if err.number <> 0 then
        if intVTErrorCount > 3 then
          objShellComplete.popup "Error #" & err.number & " - " & err.description & vbcrlf & vbcrlf & "Will attempt to submit to VirusTotal again.  If problems persist check connectivity", 30
		  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Error #" & err.number & " - " & err.description,BoolEchoLog 
          intVTErrorCount = 0
        else
          intVTErrorCount = intVTErrorCount + 1
          wscript.sleep 15000
        end if
        inLoopCounter = inLoopCounter + 1
        If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
        VT_Submit

        exit sub
      end if
    on error goto 0
    end if
  elseif BoolReportOnly = False then 'Perform HTTP GET
   
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_debug" & "" & ".txt",Date & " " & Time & " " & strDataType & strScanDataInfo & strOptionalParameter & "&APIKEY"  ,BoolEchoLog 
 

    if strresponseText = "" then
      on error resume next
      objHTTP.open "GET", strVT_APIurl & strFullAPIURL, False
	  if boolVTuseV3 = True then objHTTP.setRequestHeader "x-apikey", strAPIKey
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_Delay" & "" & ".txt",Date & " " & Time & " Looking up " & strScanDataInfo  ,BoolEchoLog 
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_time" & "" & ".txt",Date & " " & Time & " Looking up " & strScanDataInfo  ,BoolEchoLog 
      objHTTP.send
	  strDateLookupTrack = Now 'set the date time when last lookup was performed for rate limit delay      

	  if err.number <> 0 then
          objShellComplete.popup "HTTP GET: " & strVT_APIurl & vbcrlf & "Error #" & err.number & " - " & err.description & vbcrlf & vbcrlf & "Will attempt to submit to VirusTotal again.  If problems persist check connectivity", 30
		  inLoopCounter = inLoopCounter + 1
		  If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
		  VT_Submit
          exit sub
        end if

      on error goto 0
    end if
  end if   
  
  if strresponseText = "" And BoolReportOnly = false Then 'if we didn't get results from cache
    if objHTTP.status = 200 & objHTTP.responseText = "" Then
    	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VirusTotal returned 200 status code with no data.",False 
    ElseIf objHTTP.status = 403 Then
		objShellComplete.popup "403 HTTP status code was returned. This indicates a problem that needs manually corrected with the query string we are passing VirusTotal.", 16
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VirusTotal returned 403 status code. Possible problem with the query string.",False 

	ElseIf objHTTP.status = 203 then
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " VTHashLookup - VirusTotal returned 203 status code for exceeded rate limit. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
      objShellComplete.popup "203 HTTP status code was returned. Will attempt to submit to VirusTotal again after delaying for " & intDelayBetweenLookups & " seconds.  If problems persist check connectivity", 16
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VirusTotal returned 203 status code. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
      inLoopCounter = inLoopCounter + 1
      If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & "Error resubmit inLoopCounter=" & inLoopCounter,False
      VT_Submit
 
      exit sub
	ElseIf objHTTP.status = 204 then
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " VTHashLookup - VirusTotal returned 204 status code for exceeded rate limit. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
      objShellComplete.popup "204 HTTP status code was returned. You have exceed the API request rate limit." & vbcrlf & vbcrlf & "Will attempt to submit to VirusTotal again after delaying for " & intDelayBetweenLookups & " seconds.  If problems persist check connectivity",16
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VirusTotal returned 204 status code for exceeded rate limit. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
	  wscript.sleep 15001
	  inLoopCounter = inLoopCounter + 1
	  If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " Error resubmit inLoopCounter=" & inLoopCounter,False 
	  VT_Submit

      exit sub
    End if
  end if
  if strresponseText = "" Then
  	strresponseText = objHTTP.responseText
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Report_Debug" & "" & ".txt", strresponseText & vbcrlf,BoolEchoLog 
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_HTTP_Debug" & "" & ".txt", strScanDataInfo & " - " & objHTTP.status,BoolEchoLog 

  else

    inLoopCounter = inLoopCounter -1 'zero out loop as we didn't utilize the API
    If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " Didn't utilize API  inLoopCounter=" & inLoopCounter,False 
  end if
else
  strresponseText = ""
end if
tmpCountURLs = 0
intCountDomains = 0

strTmpSSline = strScanDataInfo


'empty IP line output to spreadsheet
strTmpIPlineE = "|"

if instr(strFullAPIURL,"ip=") or instr(strFullAPIURL,"domain=") then 'whois lookup for IP and domain
	If BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "Lookup Item: " & strData, false
	if instr(strFullAPIURL,"domain=") then
		strTmpRequestResponse = WhoIsDomain_Parse(strresponseText)
		if BoolWhoisDebug = True then msgbox "domain return:" & strTmpRequestResponse
		if instr(strTmpWhoIs, ".") <> instrrev(strTmpWhoIs, ".") then ' sub domain
			strTmpWhoIs = levelup(strScanDataInfo)
		end if
	else
	strTmpRequestResponse = ParseVTIPOwner(strresponseText)	
	end If
	
	whoIsPopulate strScanDataInfo
end if

if instr(strFullAPIURL,"ip=") then
      strIpDwatchLineE = MatchIpDwatchLIst(strScanDataInfo)
	  strTmpURLs = strresponseText
      strTmpIPlineE = "|" & strScanDataInfo
      if BoolDebugTrace = True then 
		logdata strDebugPath & "\VT_Debug" & "" & ".txt", StrTmpDomainOrIP & "Generating IP report" ,BoolEchoLog 
		logdata strIPreportsPath & "\VT_IPaddress_" & replace(strData,":", ".") & ".txt", strScanDataInfo & vbtab & strTmpURLs,BoolEchoLog 
	  end if

      if BoolCreateSpreadsheet = True and BoolDisableVTlookup = False then 'find greatest number of positive detections for IP address
        strTmpVTPositvLineE = ParseVTforPositives(strresponseText)       
      end if
elseif instr(strFullAPIURL,"domain=") then
      strIpDwatchLineE = MatchIpDwatchLIst(strScanDataInfo)
	  strTmpURLs = strresponseText
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_CC" & "" & ".txt", "len(strTmpCNlineE):" & len(strTmpCNlineE) ,BoolEchoLog 
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_CC" & "" & ".txt", "len(strTmpCClineE):" & len(strTmpCClineE) ,BoolEchoLog 
      if strTmpCNlineE = "" then strTmpCNlineE = "|" 
      if strTmpCClineE = "|" and len(strTmpCNlineE) > 3 then
      
        if DictCC.exists(right(ucase(strTmpCNlineE),len(strTmpCNlineE) -1)) then
          strTmpCClineE = "|" & DictCC.item(right(ucase(strTmpCNlineE),len(strTmpCNlineE) -1))
        end if
      elseif strTmpCNlineE = "|" and len(strTmpCClineE) = 3 then
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_CC" & "" & ".txt", "strTmpCNlineE:" & strTmpCNlineE ,BoolEchoLog 
        if DictRevCC.exists(right(ucase(strTmpCClineE),len(strTmpCClineE) -1)) then
          if BoolDebugTrace = True then logdata strDebugPath & "\VT_CC" & "" & ".txt", "strTmpCNlineE-1:" & right(ucase(strTmpCClineE),len(strTmpCClineE) -1) ,BoolEchoLog 
          strTmpCNlineE = "|" & DictRevCC.item(right(ucase(strTmpCClineE),len(strTmpCClineE) -1))
        end if
      end if
      if Instr(strresponseText, "ip_address" & Chr(34) & ": " & Chr(34)) then
        strTmpVTSips = ParseVTforIPaddress(strresponseText) 'get most recent IP address resolution from VirusTotal 
        if DicDomainIPmatch.exists(strScanDataInfo) Then 'check for error condition 
          MsgBox "Duplicate domain address processed! This should only occur if you edited vlist.txt"
        Else 'domain to IP Adress mapping
          DicDomainIPmatch.add strScanDataInfo, strTmpVTSips
        end if
        strTmpIPlineE = "|" & strTmpVTSips 'set spreadsheet cell value for IP address

		domainPassiveDNS strTmpVTSips 'set strRevDNS and pending items

        if strRevDNS = "|" Then 'Reverse lookup for domain name
          subReverseDNSCachewithSinkhole strScanDataInfo
        end if

      else'no IP address found/never looked up by virustotal
        strTmpIPlineE = "|"
      end if
      if BoolDebugTrace = True then logdata strDomainreportsPath & "\VT_domains_" & strData & ".txt", strScanDataInfo & vbtab & strTmpURLs,BoolEchoLog 

      
      if BoolCreateSpreadsheet = True and BoolDisableVTlookup = False then 
          strTmpVTPositvLineE = ParseVTforPositives(strresponseText)'find greatest number of positive detections for domain
      end if

      
elseif instr(strFullAPIURL,"resource=") > 0 or ishash(strFullAPIURL) = True then
  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "resource=" ,BoolEchoLog
  if BoolPost = true or ishash(strFullAPIURL) = True then'file hash/url   (BoolPost = true is for V2 API)
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "BoolPost = true" ,BoolEchoLog  
    if instr(strFullAPIURL,".") then 'not a hash
      'the data submitted was a URL
      
      strTmpURLs = "https://www.virustotal.com" & GetData(strresponseText, chr(34), chr(34) & "https://www.virustotal.com")
      if instr(strresponseText,", " & Chr(34) & "positives" & Chr(34) & ": ") then
        strNumberOfPositiveDetections = getdata(strresponseText, ",", ", " & Chr(34) & "positives" & Chr(34) & ": ")
        if strNumberOfPositiveDetections <> "0" then BoolReportWebScan = True
        if BoolDebugTrace = True then LogData strDebugPath & "\VT_URLs_" & "" & ".txt", strNumberOfPositiveDetections & " - " & strScanDataInfo & vbtab & strTmpURLs,BoolEchoLog 
        strWebScanResults = strWebScanResults & strNumberOfPositiveDetections & " - " & strScanDataInfo & vbtab & strTmpURLs & vbcrlf
    
      elseif instr(strresponseText,"Scan request successfully queued, come back later for the report") then
          if BoolDebugTrace = True then LogData strDebugPath & "\VT_URLs_" & "" & ".txt", "Scan request successfully queued, come back later for the report - " & strScanDataInfo,BoolEchoLog 
          if not DicPendingItems.Exists(strScanDataInfo) then
            if DicScannedItems.Exists(strScanDataInfo) then _
            DicScannedItems.remove(strScanDataInfo)'remove from scanned dictionary

              boolRescan = True
              DicPendingItems.Add strScanDataInfo, DicPendingItems.Count 'add to pending dictionary
              boolPendingItems = True

          end if
          
      else
        LogData strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strTmpURLs,BoolEchoLog 
        if strOptionalParameter = "&scan=1" then
          strWebScanResults = strWebScanResults & strScanDataInfo & vbtab & strTmpURLs & vbcrlf
        else
            
        end if
      end if

    Else 'the data submitted was a hash
		  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "the data submitted was a hash " & strData,BoolEchoLog            
		  if BoolSigCheckLookup = True or BoolEnCaseLookup = True or (boolSHA256csvLookup = True and len(strScanDataInfo) = 64) then 'NetAMP only supports SHA256 so must pass that as the hash value
			  
			  SigCheckSSoutput strScanDataInfo 'load sigcheck data
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "SigCheckSSoutput" ,BoolEchoLog
		  end if


      If InStr(strresponseText, chr(34) & "https://www.virustotal.com") Then    

		if BoolDisableCaching = False then CacheLookup strresponseText, "\vt\", strScanDataInfo, 45

		
		strTmpURLs = "https://www.virustotal.com" & GetData(strresponseText, chr(34), chr(34) & "https://www.virustotal.com")
        If InStr(strresponseText, chr(34) & "https://www.virustotal.com/api/v3/") Then 
			boolVT_V3 = True   
		else
			boolVT_V3 = False
		end if
		'msgbox "boolVT_V3=" & boolVT_V3
		if boolVT_V3 = True Then			
			strDateTimeLineE = ParseVT_v3ScanDate(strresponseText)
			If ispipeorempty(strCBdigSig) Then strCBdigSig = GetData(strresponseText, Chr(34), Chr(34) & "signers" & Chr(34) & ": " & Chr(34))
	        If ispipeorempty(strCBcompanyName) Then strCBcompanyName = GetData(strresponseText, Chr(34), Chr(34) & "CompanyName" & Chr(34) & ": " & Chr(34))
	        If ispipeorempty(strCBproductName) Then strCBproductName = GetData(strresponseText, Chr(34), Chr(34) & "product" & Chr(34) & ": " & Chr(34))
	        If ispipeorempty(strCBFileSize) Then 
	        	strCBFileSize = GetData(strresponseText, ",", Chr(34) & "size" & Chr(34) & ": " )
	        	If InStr(strCBFileSize, " ") > 0 Then strCBFileSize = Left(strCBFileSize,InStr(strCBFileSize, " "))
	        End if	
	        If ispipeorempty(strPE_TimeStamp) Then strPE_TimeStamp = GetData(strresponseText, " ", Chr(34) & "timestamp" & Chr(34) & ": " )
			If IsNumeric(strPE_TimeStamp) = True And strPE_TimeStamp <> "" Then
				strPE_TimeStamp = DateAdd("s", strPE_TimeStamp, "01/01/1970 00:00:00") 'epoch2date
			End If	
			If ispipeorempty(strFileTypeLineE) Then strFileTypeLineE = GetData(strresponseText, Chr(34), Chr(34) & "PEType" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strFileTypeLineE) Then strFileTypeLineE = GetData(strresponseText, Chr(34), Chr(34) & "type_description" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strMimeTypeLineE) Then strMimeTypeLineE = GetData(strresponseText, Chr(34), Chr(34) & "MIMEType" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strMimeTypeLineE) Then strMimeTypeLineE = GetData(strresponseText, Chr(34), Chr(34) & "file_type" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strMimeTypeLineE) Then strMimeTypeLineE = GetData(strresponseText, Chr(34), Chr(34) & "magic" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strCBfilePath) Then strCBfilePath = GetData(strresponseText, Chr(34), Chr(34) & "meaningful_name" & Chr(34) & ": " & Chr(34))
			If ispipeorempty(strFileIMP) Then strFileIMP = GetData(strresponseText, Chr(34), Chr(34) & "imphash" & Chr(34) & ": " & Chr(34))
		else
			strDateTimeLineE = ParseVTScanDate(strresponseText)
			if len(strDateCompare) > 7 Then strDateTimeLineE = ReformatDateTime(strDateTimeLineE, "VirusTotal") 'use the same format for datetime
		end If
		
		If strDFSlineE = "" Then
			strDFSlineE = strDateTimeLineE
		ElseIf IsDate(strDateTimeLineE) And IsDate(strDFSlineE) Then 'strDFSlineE is populated from csv import of cb response dump
			SetDateFirstSeen strDateTimeLineE 'see which date is the oldest and set strDFSlineE to it
		End If
		
		
		if BoolDisableCaching = false And strTmpCacheLineE <> "|X" then CacheLookup strresponseText, "\vt\", strScanDataInfo, intHashCacheThreashold

      Else
      	strTmpURLs = "Hash does not exist on VirusTotal"
		If InStr(strresponseText, "resource is not among the") > 0 Or InStr(strresponseText,chr(34) & "NotFoundError" & Chr(34) & ",") > 0  then
			if BoolDisableCaching = False and boolCacheVTNoExist = True then CacheLookup strresponseText, "\vt\", strScanDataInfo, intHashCacheThreashold
		end if
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Hash does not exist on VirusTotal",BoolEchoLog         	
      End If
	  
	  intHashDetectionsLineE = "|" & getPositiveDetections(strresponseText) 'get number of engines that detected the sample

      if BoolDebugTrace = True then LogData strHashReportsPath & "\" & strScanDataInfo & ".txt", strresponseText,BoolEchoLog 
	
	  If intHashDetectionsLineE <> "|" And intHashDetectionsLineE <> "|0" Then 'virus total results were returned
	      DicTmpDnames.RemoveAll
	      DictTypeNames.RemoveAll
		  setCommonDetectionName strresponseText 'performs malware scoring, sets the detection name and detection type  
	      
	      
	      if BoolCheckTrendMicro = True then VTvendorParseName strresponseText,"TrendMicro", True
	      if StrTmpVendorDetectionURL <> "" then
			  logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL,BoolEchoLog 
			  strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL & vbcrlf
	      End if
	      If boolCheckMicrosoft = True then VTvendorParseName strresponseText,"Microsoft", True
	      If boolCHeckMcAfee = True then VTvendorParseName strresponseText,"McAfee", True
	      if boolCheckSophos = True then VTvendorParseName strresponseText,"Sophos", True
	      if boolCheckESET = True then VTvendorParseName strresponseText,"ESET-NOD32", True
	      if boolCheckDrWeb  = True then VTvendorParseName strresponseText,"DrWeb", True
	      if boolCheckAvira  = True then VTvendorParseName strresponseText,"AntiVir", True
		  if boolCheckAvira  = True then VTvendorParseName strresponseText,"Avira", True
	  	  if boolCheckSymantec = True then VTvendorParseName strresponseText, "Symantec", True
	      if boolCheckFSecure = True then VTvendorParseName strresponseText, "F-Secure", True
		  if boolCheckBitdefender = True then VTvendorParseName strresponseText, "BitDefender", True
		  if boolCheckPanda = True then VTvendorParseName strresponseText, "Panda", True
		  if DisplayVendor <> "" then strDiplayVendDname = "|" & VTvendorParseName (strresponseText, DisplayVendor, False)
      End If 'End virus total results were returned

      if instr(strresponseText,"md5" & chr(34) & ": " & chr(34)) or IsHash(strScanDataInfo) then'grab file hash
	    strTmpVendorDetectionName = ""
		StrTmpVendorDetectionURL = ""
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "MD5 Returned from VT or hash " & strScanDataInfo,BoolEchoLog      
        strTmpVendorDetectionName = getdata(strresponseText,chr(34),"md5" & chr(34) & ": " & chr(34))
        if strTmpVendorDetectionName = "" Then
          if len(strScanDataInfo) = 32 then 
            strTmpVendorDetectionName = strScanDataInfo 'Hash provided is MD5
            StrTmpMD5 = strScanDataInfo
           
          elseif len(strScanDataInfo) = 40 then 'Hash provided is SHA1
              
          end if
        end if
		'multiple hash value lookup
		if instr(strresponseText,"md5" & chr(34) & ": " & chr(34)) then
			strTmpHashLookupValue = getdata(strresponseText,chr(34),"md5" & chr(34) & ": " & chr(34))
			AlienHashLookup(strTmpHashLookupValue)
			strTmpHashLookupValue = getdata(strresponseText,chr(34),"sha1" & chr(34) & ": " & chr(34))
			AlienHashLookup(strTmpHashLookupValue)
			strTmpHashLookupValue = getdata(strresponseText,chr(34),"sha256" & chr(34) & ": " & chr(34))
			AlienHashLookup(strTmpHashLookupValue)
		else'single hash lookup
			AlienHashLookup(strScanDataInfo)
		end if

        if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "strTmpVendorDetectionName = " & strTmpVendorDetectionName,BoolEchoLog
        if StrTmpVendorDetectionURL <> "" then
          if strTmpVendorDetectionName = "" then
            logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & StrTmpVendorDetectionURL,BoolEchoLog 
            strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & StrTmpVendorDetectionURL & vbcrlf
          else
            logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strTmpVendorDetectionName & vbtab & StrTmpVendorDetectionURL,BoolEchoLog 
            strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & StrTmpVendorDetectionURL & vbcrlf
          end if
        end if
        if IsHash(strTmpVendorDetectionName) then 
          if StrTmpVendorDetectionURL <> "" then
            logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL,BoolEchoLog 
            strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL & vbcrlf
          end if
          
          'when BoolLimitCBQueries = True only lookup CB if it wasn't provided with the SigCheckSSoutput 
          if BoolUseCarbonBlack = True and (BoolLimitCBQueries = True and strCBfilePath <> "") = False then checkCarBlack strTmpVendorDetectionName
          if ucase(strTmpVendorDetectionName) = "3AC9A0C8A8A5EC6D3ABA629BF66F9FB1" then
            logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & "FireEye honey binary!  This is a whitelisted file",BoolEchoLog
             strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & "FireEye honey binary!  This is a whitelisted file" & vbcrlf
          end if
        end if
      end If
      if boolEnableCuckoo = True then
			CuckooHashSubmit strData
      end if
	  if boolEnableCuckooV2 = True then
		strCuckooResponse = SubmitCuckooV2Hash(strData)
		ParseCuckooV2 strCuckooResponse
	  end if
      'strTmpVendorDetectionName should always be the md5 in this section
      if ishash(strTmpVendorDetectionName) = True and len(strTmpVendorDetectionName) = 32 then 
         if boolUseXforce = True then
            strTmpXforce = CheckXForce(strTmpVendorDetectionName)
           if BoolDebugTrace = True then logdata strHashReportsPath & "\IBM_MalMD5_" & strData & ".txt", strTmpVendorDetectionName & vbtab & strTmpXforce,BoolEchoLog 
           if strTmpXforce <> "" then
            if strXforce_Output = "" then
              strXforce_Output = "https://exchange.xforce.ibmcloud.com/malware/" & strTmpVendorDetectionName
            else
              strXforce_Output = strXforce_Output & vbcrlf & "https://exchange.xforce.ibmcloud.com/malware/" & strTmpVendorDetectionName
            end if
           end if
         end if
         
        'Threat Crowd lookups
        if boolUseThreatCrowd = True And tcHashLookedUp = false then
           strTmpTCrowd = ThreatCrowdHashLookup(strTmpVendorDetectionName)      
        end If
        
        'Proofpoint ET Intelligence lookups
        if BoolUseETIntelligence = True And etHashLookedUp = false Then 
          PPointSubmit "md5"
          if boolCheckProofpointIDS = True then strPPidsLineE = CheckProofpIDS("md5", strTmpVendorDetectionName)
        end if 
      end if                 


 	  
	  
      
      logdata strDebugPath & "\VT_URLs_" & "" & ".txt", getPositiveDetections(strresponseText) & " - " & strScanDataInfo & vbtab & strTmpURLs,BoolEchoLog 
      strThisScanResults = strThisScanResults & getPositiveDetections(strresponseText) & " - " & strScanDataInfo & vbtab & strTmpURLs & vbcrlf

      if strScanDataInfo <> "" then'Skip if nothing to scan
        'log metascan results
        If BoolMetascan = True then 
            strtmpMetascanReslts = SubmitMetaScan(strScanDataInfo)
            if strtmpMetascanReslts <> "Metadefender has never scanned this file hash" and strtmpMetascanReslts <> "Metadefender won't give results back" then
              logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strtmpMetascanReslts, BoolEchoLog
              strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & strtmpMetascanReslts & vbcrlf
            end If  
        End if    
        if BoolUseThreatGRID = True then
          strtmpMetascanReslts = SubmitThreatGRID(strScanDataInfo)
          if strtmpMetascanReslts <> "ThreatGRID has never seen this file hash" and strtmpMetascanReslts <> "ThreatGRID won't give results back" then
            logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strtmpMetascanReslts, BoolEchoLog
            strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & strtmpMetascanReslts & vbcrlf
            strTmpTGlineE = "|X"

          else
            strTmpTGlineE = "|"                
          end If
        end if
        if BoolUseMalShare = True then
          MalShareHashLookup  strScanDataInfo       
        end if
        if BoolNSRLLookup  = True then
          strtmpReslts = NSRL_Lookup(strScanDataInfo)
          if strtmpResults = True then
            strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & "Hash is in the NSRL" & vbcrlf
          end if
        end if	          
      end if
    end if
    
    
  else

  end if
end if

'Perform domain lookups
if instr(strFullAPIURL,"domain=") then
  'Perform domain DBL lookups
  if BoolDNS_BLchecks = True and boolDisableDomain_BLchecks = False then
    tmpParentDomain = LevelUp(strData) 'GetParentDomain
	for RBL_loop = 0 to 2
      if RBL_loop = 0 and boolEnableZDBL = True then StrTmpRBLOutput = RBL_Lookup(strData, ".dbl.spamhaus.org " & zenDNS) ' it is optional and not necessary to strip the hostname down to query the actual domain only. 
      if RBL_loop = 1 and enableURIBL = True then StrTmpRBLOutput = RBL_Lookup(tmpParentDomain, ".multi.uribl.com " & uriblDNS )
      if RBL_loop = 2 and enableSURBL = True then StrTmpRBLOutput = RBL_Lookup(strData, ".multi.surbl.org " & surblDNS)
      if StrTmpRBLOutput <> "" then
        if StrRBL_Results = "" then
          StrRBL_Results = StrTmpRBLOutput
        else
          StrRBL_Results = StrRBL_Results & vbcrlf & StrTmpRBLOutput
        end if
        if RBL_loop = 0 then strTmpZDBLlineE = "|X"
		if RBL_loop = 1 then strTmpURIBLlineE = "|X"
      else
        if RBL_loop = 0 and boolEnableZDBL = True then strTmpZDBLlineE = "|"              
      end if
    next
  end if
  
  'Check dynamic DNS

  If BoolDDNS_Checks = True then
    if instr(strData, ".") then
      ArrayTmpDDNS = split(strData, ".")
      for ddnsloop = 0 to 1
        if ddnsloop = 0 then
          strTmpDDNS = ArrayTmpDDNS(ubound(ArrayTmpDDNS)-1) & "." & ArrayTmpDDNS(ubound(ArrayTmpDDNS))
        elseif ubound(ArrayTmpDDNS) > 2 then
          strTmpDDNS = ArrayTmpDDNS(ubound(ArrayTmpDDNS)-2) & "." & ArrayTmpDDNS(ubound(ArrayTmpDDNS)-1) & "." & ArrayTmpDDNS(ubound(ArrayTmpDDNS))
        else
          exit for
        end if

        if DictDDNS.exists(strTmpDDNS) = True then

          strDDNSLineE = "|X"
          if strDDNS_Output = "" then
            strDDNS_Output = strTmpDDNS
          else
            strDDNS_Output = strDDNS_Output & vbCrLf & strTmpDDNS
          end if
          exit for
        else
          strDDNSLineE = "|"
        end if
      next
    end if
  end if
  
 'Perform x-force lookups 
 if boolUseXforce = True then 
   strTmpXforce = CheckXForce(strData)
   logdata strIPreportsPath & "\IBM_domain_" & strData & ".txt", strScanDataInfo & vbtab & strTmpXforce,BoolEchoLog 
   if strTmpXforce <> "" then
    if strXforce_Output = "" then
      strXforce_Output = "https://exchange.xforce.ibmcloud.com/url/" & strData
    else
      strXforce_Output = strXforce_Output & vbcrlf & "https://exchange.xforce.ibmcloud.com/url/" & strData
    end if
   end if
 end if
 
 'Threat Crowd lookups
 if boolUseThreatCrowd = True then
     strTmpTCrowd = CheckThreatCrowd("domain", strData)
   if BoolDebugTrace = true then logdata strdomainreportsPath & "\TCrowd_domain_" & strData & ".txt", strScanDataInfo & vbtab & strTmpTCrowd,BoolEchoLog 
   if strTmpTCrowd <> "" then
    if strTCrowd_Output = "" then
      strTCrowd_Output = "https://www.threatcrowd.org/domain.php?domain=" & strData
    else
      strTCrowd_Output = strTCrowd_Output & vbcrlf & "https://www.threatcrowd.org/domain.php?domain=" & strData
    end if
    strTMPTCrowdLine = "|X"
   end if 
 end if

	
 'Proofpoint ET Intelligence lookups
 if BoolUseETIntelligence = True then 
  PPointSubmit "domain"
  if boolCheckProofpointIDS = True then strPPidsLineE = CheckProofpIDS("domain", strdata)
 end if 
 
 'get VT categories for domain
 strCategoryLineE = GetWebCategoryfromVT (strresponseText)

end if

if instr(strFullAPIURL,"ip=") or instr(strFullAPIURL,"domain=") then
  if instr(strFullAPIURL,"ip=") then StrTmpDomainOrIP = "IP "
  if instr(strFullAPIURL,"domain=") then StrTmpDomainOrIP = "domain "
  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", StrTmpDomainOrIP & "identified for processing" ,BoolEchoLog 
  if instr(strresponseText,", " & Chr(34) & "positives" & Chr(34) & ": ") < 1 then 
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "No positive detections found." ,BoolEchoLog 
  else
	Dim lastX
	intHashlookupCount = 0
	DicTmpDnames.RemoveAll
	DictTypeNames.RemoveAll
	Erase ArrayDnameLineE'clear array for each IP address 
	redim ArrayDnameLineE(cint(intDetectionNameCount) -1 + intaddDNameCount)'clear array for each IP address 
	
	for intPTVFT = 0 to 3

	  if intPTVFT = 0 then 
		strDetectSection = getdata(strresponseText, "]", chr(34) & "detected_downloaded_samples" & chr(34) & ": [")
		intPositiveDetectSection = 0
	  elseif intPTVFT = 1 then 
		strDetectSection = getdata(strresponseText, "]", chr(34) & "detected_referrer_samples" & chr(34) & ": [")
		intPositiveDetectSection = 1
	  elseif intPTVFT = 2 then 
		strDetectSection = getdata(strresponseText, "]", chr(34) & "detected_communicating_samples" & chr(34) & ": [")
		intPositiveDetectSection = 3
	  elseif intPTVFT = 3 then 
		strDetectSection = getdata(strresponseText, "]", chr(34) & "detected_urls" & chr(34) & ": [")
		intPositiveDetectSection = 2
	  end if

		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "IPorDomain" & ".txt", strDetectSection, false
		arrayIPresults = Split(strDetectSection,Chr(34) & "positives" & Chr(34) & ": ")
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "spliting at positives.  Total splits " & ubound(arrayIPresults),BoolEchoLog 

		if BoolDebugTrace = True then logdata strDebugPath & "\VT_IPdomain_hashlist.txt", strdata ,BoolEchoLog

		for intCountArrayIP = 1 to ubound(arrayIPresults) 'loop through positive detections
		  if lastX > intCountArrayIP then 
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Bug where last intCountArrayIP = " & lastX & "intCountArrayIP = " & intCountArrayIP,BoolEchoLog 
			exit for
		  end if
		  '"detected_downloaded_samples"  
		  '"detected_referrer_samples"
		  '"detected_urls"
		  'intPositiveDetectSection

					  
		  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt",intCountArrayIP & " = 1 to " &  ubound(arrayIPresults),BoolEchoLog 
		  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","Detection Count=" &  left(arrayIPresults(intCountArrayIP), instr(arrayIPresults(intCountArrayIP),",")-1),BoolEchoLog 
		  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","Left char:" &  left(arrayIPresults(intCountArrayIP), instr(arrayIPresults(intCountArrayIP),",")-1),BoolEchoLog 
		  if "0" <> left(arrayIPresults(intCountArrayIP), instr(arrayIPresults(intCountArrayIP),",")-1) then'if a positive detection (anything but 0). Lookup value is in the item before the positive value in the array
			

			 intTmpHashPositives =  left(arrayIPresults(intCountArrayIP), instr(arrayIPresults(intCountArrayIP),",")-1)
			strTmpIPurl= getdata(arrayIPresults(intCountArrayIP-1), chr(34), "{" & chr(34) & "url" & chr(34) & ": " & chr(34))'get url. URLs are listed before the positive split hence intCountArrayIP-1
			if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt",strTmpIPurl <> "",BoolEchoLog
			if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt",strTmpIPurl <> "",BoolEchoLog
			if strTmpIPurl <> "" Then
				strURLWatchLineE = MatchURLwatchList(strURLWatchLineE, strTmpIPurl)
				if boolLogURLs = True then logdata strReportsPath & "\URLs_" & UniqueString & ".log",strTmpIPurl, false
			end if
			if strTmpIPurl <> "" and left(arrayIPresults(intCountArrayIP), 1) <> "0" then 'only grab positive detections
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","tmpCountURLs = " & tmpCountURLs,BoolEchoLog 
			  tmpCountURLs = tmpCountURLs +1
			  'bug formating change 
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "_change1" & ".txt",arrayIPresults(intCountArrayIP-1), False
			
			  if not dicIPurls.Exists(strTmpIPurl) then _
			  dicIPurls.Add strTmpIPurl, dicIPurls.Count end If 'add to dictionary if not already there
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","strTmpIPurl = " & strTmpIPurl,BoolEchoLog 
				
			elseif left(arrayIPresults(intCountArrayIP-1), 1) <> "0" then 'only grab positive detections
				strTmpIPurl = getdata(arrayIPresults(intCountArrayIP), chr(34), chr(34) & "sha256" & chr(34) & ": " & chr(34))'get hash. hashes are listed after the positive split hence no intCountArrayIP-1
				if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","strTmpIPurl=" & strTmpIPurl, False 
				if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","intPositiveDetectSection=" & intPositiveDetectSection, False
				if boolDebugTrace = True then logdata strDebugPath & "\VT_Debug.txt", "intDetectionNameCount=" & intDetectionNameCount & "|" & "intHashlookupCount=" & intHashlookupCount & "|" & "intTmpHashPositives=" & intTmpHashPositives & "|" & "intHashPositiveThreashold=" & intHashPositiveThreashold & "|" &  "=" & intDetectionCategory, false
				 If intPositiveDetectSection = 0 then
				   if not DicHashDownloaded.Exists(strTmpIPurl) then _
				   DicHashDownloaded.add strTmpIPurl, DicHashDownloaded.Count end If 'add to dictionary if not already there

				   if cint(intDetectionNameCount) > intHashlookupCount and cint(intTmpHashPositives) > cint(intHashPositiveThreashold) and cint(intDetectionCategory) = 0 then DetectionNameSSlineE = DetectionNameSSline(strTmpIPurl, intPositiveDetectSection) 'spreadsheet line output
				 elseif intPositiveDetectSection =1 then
				   if not DicHashReferrer.Exists(strTmpIPurl) then _
				   DicHashReferrer.add strTmpIPurl, DicHashReferrer.Count end If 'add to dictionary if not already there
					if cint(intDetectionNameCount) > intHashlookupCount and intTmpHashPositives > intHashPositiveThreashold and intDetectionCategory = 1 then 
						
						DetectionNameSSlineE = DetectionNameSSline(strTmpIPurl, intPositiveDetectSection) 'spreadsheet line output
					end if
				 elseif intPositiveDetectSection =3 then
				   if not DicHashComm.Exists(strTmpIPurl) then _
				   DicHashComm.add strTmpIPurl, DicHashComm.Count end If 'add to dictionary if not already there
				   if cint(intDetectionNameCount) > intHashlookupCount and intTmpHashPositives > intHashPositiveThreashold and intDetectionCategory = 2 then 
						DetectionNameSSlineE = DetectionNameSSline(strTmpIPurl, intPositiveDetectSection) 'spreadsheet line output for IP/Domain detection names
				   end if
				 elseif intPositiveDetectSection = 2 then
				   if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","DIcHashes.Exists(strTmpIPurl)=" & DIcHashes.Exists(strTmpIPurl), False
				   if not DIcHashes.Exists(strTmpIPurl) then 
					DIcHashes.add strTmpIPurl, DIcHashes.Count 
					if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","DIcHashes.Count =" & DIcHashes.Count, False
					end If 'add to dictionary if not already there
				 end if             
			end if

		  end if
	 
		  lastintCountArrayIP = intCountArrayIP
		next
	next
    strDomainListOut = ""
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Processing host names",BoolEchoLog 
    'Split hostnames and check which ones are malicious
    if instr(strresponseText,"hostname" & chr(34) & ": " & chr(34)) then
      ArrayHostNames = Split(strresponseText,"hostname" & chr(34) & ": " & chr(34))
      intCountDomains = 0
	  intCountOutDomain = 0
		'msgbox "ubound(ArrayHostNames)=" & ubound(ArrayHostNames)

        For Each Item In dicIPurls
			
			strTmpCountDomain = getdata(Item, "/", "//")
			if DictTrackDomain(strTmpCountDomain) = false then  'only count malicious domains once. This also checks against watchlists
				intCountDomains = intCountDomains +1
				intCountOutDomain = intCountOutDomain + 1
              if strDomainListOut = "" and intCountOutDomain < 5 then 'add malicious domains before adding non-detected
                strDomainListOut = "|" & strTmpCountDomain
              elseif intCountOutDomain < 5 then
                 strDomainListOut = AppendValuesList(strDomainListOut,strTmpCountDomain,";")
              end if                  
			end if
        next
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt","intCountDomains = " & intCountDomains, False 
	   'msgbox "intCountDomains=" & intCountDomains
	   'msgbox "strDomainListOut=" & strDomainListOut
	   
       'the following code to grab domains as an example when malicious domains don't exist
	   if intCountOutDomain < 4 then
         for x = 1 to ubound(ArrayHostNames)
		  if DictTrackDomain(ArrayHostNames(x)) = false then 
			intCountDomains = intCountDomains +1
			  if intCountOutDomain < 5 then 

				 strDomainListOut = AppendValuesList(strDomainListOut,left(ArrayHostNames(x),instr(ArrayHostNames(x), chr(34))-1),";")

				  intCountOutDomain = intCountOutDomain + 1
			  end if
		  end if
		  next
       end if
    end if

   'End split hostnames and check which ones are malicious


    if strDomainListOut <> "" then 
       if BoolDebugTrace = True then LogData strDebugPath & "\VT_SS_IP-domain.log", strTmpSSreturn & " - " & strDomainListOut, false

    else
       if BoolDebugTrace = True then LogData strDebugPath & "\VT_SS_IP-domain.log", strTmpSSreturn & " - " & "strDomainListOut is null", false
    end if
  '
  
    lastX = 0
    erase arrayIPresults
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Finished processing positive detections for " & StrTmpDomainOrIP,BoolEchoLog 
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "DIcHashes.Count=" & DIcHashes.Count,BoolEchoLog 
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "DicHashDownloaded.Count=" & DicHashDownloaded.Count,BoolEchoLog 
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "DicHashReferrer.Count=" & DicHashReferrer.Count,BoolEchoLog 
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "DicHashComm.Count=" & DicHashComm.Count,BoolEchoLog 
    if DIcHashes.Count > 0 then
      'strTIScanResults = strTIScanResults & DIcHashes.Count & " unique hashes detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
    end if
    if DicHashDownloaded.Count > 0 then
      if DicHashDownloaded.Count = 1 then
        strTIScanResults = strTIScanResults & DicHashDownloaded.Count & " unique hash detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
      else
        strTIScanResults = strTIScanResults & DicHashDownloaded.Count & " unique hashes detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
      end if
	  LogHashes DicHashDownloaded, "Down", strData
    end if
    if DicHashReferrer.Count > 0 then
      if DicHashReferrer.Count = 1 then
        strTIScanResults = strTIScanResults & DicHashReferrer.Count & " unique hash detected as malicious referring back to " & StrTmpDomainOrIP & strData & vbcrlf
      else
        strTIScanResults = strTIScanResults & DicHashReferrer.Count & " unique hashes detected as malicious referring back to " & StrTmpDomainOrIP & strData & vbcrlf
      end if
	  LogHashes DicHashReferrer, "Referr", strData
    end if
    if DicHashComm.Count > 0 then
      if DicHashComm.Count = 1 then
        strTIScanResults = strTIScanResults & DicHashComm.Count & " unique hash detected as malicious connecting back to " & StrTmpDomainOrIP & strData & vbcrlf
      else
        strTIScanResults = strTIScanResults & DicHashComm.Count & " unique hashes detected as malicious connecting back to " & StrTmpDomainOrIP & strData & vbcrlf
      end if
	  LogHashes DicHashComm, "Comm", strData
    end if    
            
    if tmpCountURLs = 100 then
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_TI_" & "" & ".txt", tmpCountURLs & " or greater unique URLs detected as malicious hosted at " & StrTmpDomainOrIP & strData,BoolEchoLog
      strTIScanResults = strTIScanResults & tmpCountURLs & " or greater unique URLs detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
    elseif tmpCountURLs = 1 then
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_TI_" & "" & ".txt", tmpCountURLs & " unique URL detected as malicious hosted at " & StrTmpDomainOrIP & strData,BoolEchoLog
      strTIScanResults = strTIScanResults & tmpCountURLs & " unique URL detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
    
    else
      if BoolDebugTrace = True then logdata strDebugPath & "\VT_TI_" & "" & ".txt", tmpCountURLs & " unique URLs detected as malicious hosted at " & StrTmpDomainOrIP & strData,BoolEchoLog
      strTIScanResults = strTIScanResults & tmpCountURLs & " unique URLs detected as malicious hosted at " & StrTmpDomainOrIP & strData & vbcrlf
    end if

    
    if tmpCountURLs <> 0 then
        if instr(strFullAPIURL,"ip=") then 
          if BoolDebugTrace = True then logdata strDebugPath & "\VT_IP_" & "" & ".txt", "https://www.virustotal.com/en/ip-address/" & strData & "/information/",BoolEchoLog
          strIPlinks = strIPlinks & "https://www.virustotal.com/en/ip-address/" & strData & "/information/" & vbcrlf
        elseif instr(strFullAPIURL,"domain=") then 
          if BoolDebugTrace = True then logdata strDebugPath & "\VT_domain_" & "" & ".txt", "https://www.virustotal.com/en/domain/" & strData & "/information/",BoolEchoLog
          strDomainLinks = strDomainLinks & "https://www.virustotal.com/en/domain/" & strData & "/information/" & vbcrlf            
        end if
    end if


    if instr(strresponseText,"hostname" & chr(34) & ": " & chr(34)) then
       if int(intCountDomains) = 1 then 
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_TI_" & "" & ".txt", intCountDomains & " unique domain detected as malicious hosted at IP " & strData,BoolEchoLog  
        strTIScanResults = strTIScanResults & intCountDomains & " unique domain detected as malicious hosted at IP " & strData & vbcrlf
       else
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_TI_" & "" & ".txt", intCountDomains & " unique domains detected as malicious hosted at IP " & strData,BoolEchoLog  
        strTIScanResults = strTIScanResults & intCountDomains & " unique domains detected as malicious hosted at IP " & strData & vbcrlf
       end if
     end if
  end if  
  if BoolDisableVTlookup = False then
	strTmpVTTIlineE =  "|" & DicHashDownloaded.Count & "|" & DicHashReferrer.Count & "|" & DicHashComm.Count & "|" & tmpCountURLs & "|" & intCountDomains
  end if
  DicHashDownloaded.RemoveAll
  DicHashReferrer.RemoveAll
  DicHashComm.RemoveAll
  tmpCountURLs = 0
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug_TI_b" & "" & ".txt", "-----" & vbcrlf & "VirusTotal IP information:" & vbCrLf & strTIScanResults & vbcrlf ,BoolEchoLog 

Set objHTTP = Nothing

'Store SQLite data for domains
if instr(strFullAPIURL,"domain=") then
  Set cmd1 = createobject("ADODB.Command")
  StrNow = DateDiff("s", "01/01/1970 00:00:00", Now())  
  set objparameter0 = cmd1.createparameter("@created", 129, 1, len(StrNow),StrNow)
  set objparameter1 = cmd1.createparameter("@lastupdate", 129, 1, len(StrNow),StrNow)
  if len(strresponseText) > 0 then 
    arrayScoreCheck = split(strTmpVTTIlineE, "|")
    'only cache VT results that have positive detections.
    for each intScoreItem in arrayScoreCheck
      if isnumeric(intScoreItem) then
        if cint(intScoreItem) > 0 then 
          set objparameter2 = cmd1.createparameter("@VTcache", 129, 1, len(strresponseText),strresponseText)
          exit for
        end if
      end if
    next  
  end if
  if len(strTMPTCrowdLine) = 2 then set objparameter3 = cmd1.createparameter("@ThreatCrowd", 3, 1, ,1)

  if len(strRevDNS) > 1 then set objparameter4 = cmd1.createparameter("@strRevDNS", 129, 1, len(strRevDNS)-1,right(strRevDNS,len(strRevDNS) -1))
  if len(strTmpIPlineE) > 1 then set objparameter5 = cmd1.createparameter("@IPaddress", 129, 1, len(strTmpIPlineE)-1,right(strTmpIPlineE,len(strTmpIPlineE) -1))
  if len(strTmpPPointLine) > 1 then set objparameter6 = cmd1.createparameter("@ETintel", 129, 1, len(strTmpPPointLine)-1,right(strTmpPPointLine,len(strTmpPPointLine) -1))
  if len(strTmpIXFlineE) > 1 then set objparameter7 = cmd1.createparameter("@x-force", 129, 1, len(strTmpIXFlineE)-1,right(strTmpIXFlineE,len(strTmpIXFlineE) -1)) 'no longer used
  if len(strTmpSinkHole) > 1 then set objparameter8 = cmd1.createparameter("@Sinkhole", 129, 1, len(strTmpSinkHole)-1,right(strTmpSinkHole,len(strTmpSinkHole) -1))

 'UpdateDomainVendTable strdomainName, objCreatedDate, objLastUpDate, objVTdomain, objTCdomain, objRevDomain, objCountryNameDomain,	CountryCodeDomain, objRegionNameDomain, objRegionCodeDomain, objCityNameDomain, objCreationDate, objWHOISName, objIPaddress, objETdomain, ObjXForce, ObjSinkhole)
  if BoolUseSQLite = True And BoolDisableCaching = false And boolCacheDomain = True then
	UpdateDomainVendTable strData    , objparameter0, objparameter1, objparameter2, objparameter3, objparameter4,                "",	             ""  ,         ""         ,            ""      ,                "",              "",           "", objparameter5, objparameter6, objparameter7, objparameter8
  end if
  set cmd1 = nothing
end if
end sub



function LogData(TextFileName, TextToWrite,EchoOn)
Set fsoLogData = CreateObject("Scripting.FileSystemObject")
if TextFileName = "" then
  msgbox "No file path passed to LogData"
  exit function
end if
if EchoOn = True then wscript.echo TextToWrite
  If fsoLogData.fileexists(TextFileName) = False Then
      'Creates a replacement text file 
      on error resume next
      fsoLogData.CreateTextFile TextFileName, True
      if err.number <> 0 and err.number <> 53 then 
        logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Error logging to " & TextFileName & " - " & err.description,False 
        objShellComplete.popup err.number & " " & err.description & vbcrlf & TextFileName,,"Logging error", 30
        exit function
      end if
      on error goto 0
  End If
if TextFileName <> "" then

  on error resume next
  Set WriteTextFile = fsoLogData.OpenTextFile(TextFileName,ForAppending, False)
  WriteTextFile.WriteLine TextToWrite
  WriteTextFile.Close
  if err.number <> 0 then 
    on error goto 0
    
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.CharSet = "utf-16"
  objStream.Open
  objStream.WriteText TextToWrite
  on error resume next
  objStream.SaveToFile TextFileName, 2
  if err.number <> 0 then msgbox err.number & " - " & err.message & " Problem writing to " & TextFileName
  if err.number <> 0 then 
    objShellComplete.popup "problem writting text: " & TextToWrite, 30
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " problem writting text: " & TextToWrite,False 
  end if
  on error goto 0
  Set objStream = nothing
  end if
end if
Set fsoLogData = Nothing
End Function


Function RemoveTextline(StrRTFpath, strToRemove)
Dim strReturnWithoutMissingline 
  if objFSO.fileexists(StrRTFpath)  = True then
    Set objTRLfile = objFSO.OpenTextFile(StrRTFpath)

    Do While Not objTRLfile.AtEndOfStream
      if not objTRLfile.AtEndOfStream then 'read file
          On Error Resume Next
          strFTLData = objTRLfile.ReadLine 
          on error resume next
          if instr(lcase(strFTLData), lcase(strToRemove)) = 0 and strFTLData <> "" then 
            if strReturnWithoutMissingline = "" then
              strReturnWithoutMissingline = strFTLData
            else
              strReturnWithoutMissingline = strReturnWithoutMissingline & vbcrlf & strFTLData
            end if
          end if
      end if
    loop
    objTRLfile.close
  end if
RemoveTextline = strReturnWithoutMissingline
objTRLfile = Nothing
end function


function LogOverwriteData(TextFileName, TextToWrite,EchoOn)
Set fsoLogOverwriteData = CreateObject("Scripting.FileSystemObject")
if EchoOn = True then wscript.echo TextToWrite
  If fsoLogOverwriteData.fileexists(TextFileName) = False Then
      'Creates a replacement text file 
      on error resume next
      fsoLogOverwriteData.deletefile TextFileName
      fsoLogOverwriteData.CreateTextFile TextFileName, True
      if err.number <> 0 and err.number <> 53 then msgbox err.number & " " & err.description & vbcrlf & TextFileName
      on error goto 0
  End If
if TextFileName <> "" then


  Set WriteTextFile = fsoLogOverwriteData.OpenTextFile(TextFileName,forwriting, False)
  on error resume next
  WriteTextFile.WriteLine TextToWrite
  if err.number <> 0 then 
    on error goto 0
    WriteTextFile.Close
  Dim objOverwriteStream
  Set objOverwriteStream = CreateObject("ADODB.Stream")
  objOverwriteStream.CharSet = "utf-16"
  objOverwriteStream.Open
  objOverwriteStream.WriteText TextToWrite
  objOverwriteStream.SaveToFile TextFileName, 2
  Set objOverwriteStream = nothing
  end if
end if
Set fsoLogOverwriteData = Nothing
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


Function GetDataOn(contents, ByVal EndOfStringChar, ByVal EndOfStringCharAlt, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= instr(contents, MatchString)
  if X >0 then
    
    strSubContents = Mid(contents, x + MatchStringLength, len(contents) - MatchStringLength - x +1)
    EOScharLocation = instr(strSubContents,EndOfStringChar)
    EOScharLocationAlt = instr(strSubContents,EndOfStringCharAlt)
    if EOScharLocation > 0 or EOScharLocationAlt > 0 then
      if EOScharLocation < 1 or (EOScharLocationAlt > 0 and EOScharLocationAlt < EOScharLocation) then
        GetDataOn = Mid(contents, x + MatchStringLength, EOScharLocationAlt -1)
      else
        GetDataOn = Mid(contents, x + MatchStringLength, EOScharLocation -1)
      end if
      exit function
    else
      GetDataOn = Mid(contents, x + MatchStringLength, len(contents) -x -1)
      exit function
    end if
    
  end if
GetDataOn = ""
end Function


Function GetData(contents, ByVal EndOfStringChar, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= instr(contents, MatchString)

  if X >0 then
    strSubContents = Mid(contents, x + MatchStringLength, len(contents) - MatchStringLength - x +1)
    if instr(strSubContents,EndOfStringChar) > 0 then
      GetData = Mid(contents, x + MatchStringLength, instr(strSubContents,EndOfStringChar) -1)
      exit function
    ElseIf Len(strSubContents) > 0 Then 'if equal to zero then match string is very last char
      GetData = Mid(contents, x + MatchStringLength, len(contents) -x -1)
      exit function
    end if
  end if
GetData = ""

end Function


Function isIPaddress(strIPaddress)
DIm arrayTmpquad
Dim boolReturn_isIP
boolReturn_isIP = True
if instr(strIPaddress,".") then
  arrayTmpquad = split(strIPaddress,".")
  for each item in arrayTmpquad
    if isnumeric(item) = false then boolReturn_isIP = false
  next
else
  boolReturn_isIP = false
end if
if boolReturn_isIP = false then
	boolReturn_isIP = isIpv6(strIPaddress)
end if
isIPaddress = boolReturn_isIP
END FUNCTION



Function CheckSymantecEncyclopedia(strSymantecDetectionName)
select case strSymantecDetectionName
  case "Trojan.Gen"
    exit function
  case "Trojan.Gen.2"
    exit function
  case "WS.Reputation.1"
    exit function  
  case "Trojan Horse"
    exit function        
end select
if instr(lcase(strSymantecDetectionName), "trojan.adh") then exit function
if instr(lcase(strSymantecDetectionName), "smg.heur!") then exit function
if instr(lcase(strSymantecDetectionName), "suspicious.cloud") then exit function
if instr(lcase(strSymantecDetectionName), "trojan.gen.smh") then exit function
strReturnURL = TIAprocess(DictSymantecEncyclopedia, "Symantec", strSymantecDetectionName, strSymanteclineE)
CheckSymantecEncyclopedia = strReturnURL
End Function


Function rGetData(contents, ByVal EndOfStringChar, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= instrRev(contents, MatchString) -1
  if X >0 then
    if instrRev(left(contents, x),EndOfStringChar) > 0 then
      rGetData = Mid(contents, instrRev(left(contents, x),EndOfStringChar) +len(EndOfStringChar),x - instrRev(left(contents, x),EndOfStringChar) -len(EndOfStringChar) +1)
      exit function
    else
      rGetData = left(contents,x)
      'msgbox "failed match:" & left(contents,x -1)
      exit function
    end if
    
  end if
rGetData = ""
end Function


Function SubmitMetaScan(strSMetascanHash)
Dim strReturnMetaScanResults
strReturnMetaScanResults = ""
strReturnMetaScanResults = CheckMetaScan(strSMetascanHash)
if strReturnMetaScanResults = "error" then
  intMScount = 0
  do while strReturnMetaScanResults = "error" and intMScount < 7 or strReturnMetaScanResults = "403" and intMScount < 7
    if strReturnMetaScanResults = "403" and BoolCreateSpreadsheet = True then 
      logdata strDebugPath & "\Meta_IP.log", "Sleeping, limit reached.",False 
      wscript.sleep 600000
    end if  
    strReturnMetaScanResults = CheckMetaScan(strSMetascanHash)
    intMScount = intMScount +1
  loop
end if
if strReturnMetaScanResults = "error" then
  SubmitMetaScan = "Metadefender won't give results back"
else
  if BoolCreateSpreadsheet = true and intVTListDataType = 1 and BoolUseExcel = False and strReturnMetaScanResults <> "" then 'IP/domain
    SubmitMetaScan = "x"
  else
    SubmitMetaScan = strReturnMetaScanResults
  end if
end if
end function


Function CheckMetaScan(strMSfilehash)
Dim objHTTP_MetaScan
Dim strHTTP_MetaResponse
Dim strTmpMetaSresults
Dim strTmpIPgeoInfo
Dim intMSPositiveDetectionCount
Set objHTTP_MetaScan = CreateObject("MSXML2.ServerXMLHTTP")
strHTTP_MetaResponse = ""

BoolPost_MetaScan = False
if BoolPost_MetaScan = true then
  
  objHTTP_MetaScan.open "POST", "https://api.metadefender.com/v2/file", False
  objHTTP_MetaScan.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
  objHTTP_MetaScan.setRequestHeader "apikey", strMetaAPIkey

  objHTTP_MetaScan.send "hash=" & strMSfilehash
else
  if isIPaddress(strMSfilehash) then
    objHTTP_MetaScan.open "GET", "https://api.metadefender.com/v1/scan/" & strMSfilehash, False
  else

    if ishash(strMSfilehash) and BoolDisableCacheLookup = false then _
     strHTTP_MetaResponse = CacheLookup("", "\ms\", strMSfilehash, intHashCacheThreashold)
    if strHTTP_MetaResponse = "" then _
     objHTTP_MetaScan.open "GET", "https://api.metadefender.com/v2/hash/" & strMSfilehash, False
  end if
  

  if strHTTP_MetaResponse = "" then
    objHTTP_MetaScan.setRequestHeader "apikey", strMetaAPIkey
  on error resume next
    objHTTP_MetaScan.send
    
    if objHTTP_MetaScan.status = 403 then
      CheckMetaScan = "403"
       logdata strDebugPath & "\Meta_SS_IP.log", Date & " " & Time & "_" & strMSfilehash & vbtab & "status code- 403: IP/URI lookup limit reached, try again later",False 
       exit function
    elseif err.number = "-2147012894" then
      'msgbox "Time out"
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "_" & strMSfilehash & " Metascan has timed out. - " & err.description,False 
      CheckMetaScan = "error"
    elseif err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "_" & strMSfilehash & " Metascan has timed out. - " & err.description,False 
      'msgbox err.number   
    end if
    on error goto 0
    strHTTP_MetaResponse = objHTTP_MetaScan.responseText
    if ishash(strMSfilehash) then
      'could move this to only cache known files but to limit lookups now cache everything
      if BoolDisableCaching = False then CacheLookup strHTTP_MetaResponse, "\ms\", strMSfilehash, intHashCacheThreashold
    end if
  end if
end if

on error resume next

if err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Metascan HTTP unknown error. - " & err.description,False 
end if
on error goto 0

if instr(strHTTP_MetaResponse, "Unauthorized: Access is denied due to invalid credentials.") then
  'wscript.echo "invalid credentials"
  CheckMetaScan = "error"
elseif isIPaddress(strMSfilehash) then
  logdata strDebugPath & "\Meta_IP.log", strHTTP_MetaResponse,False 
  if instr(strHTTP_MetaResponse,"botnet") then strTmpMetaSresults = strTmpMetaSresults & "botnet /, "
  if instr(strHTTP_MetaResponse,"malware") then strTmpMetaSresults = strTmpMetaSresults & "malware /, "
  if instr(strHTTP_MetaResponse,"phishing") then strTmpMetaSresults = strTmpMetaSresults & "phishing /, "
  if instr(strHTTP_MetaResponse,"scanner") then strTmpMetaSresults = strTmpMetaSresults & "scanner /, "
  if instr(strHTTP_MetaResponse,"spam") then strTmpMetaSresults = strTmpMetaSresults & "spam /, "
  if instr(strHTTP_MetaResponse,"suspicious") then strTmpMetaSresults = strTmpMetaSresults & "suspicious /, "
  if instr(strHTTP_MetaResponse,"whitelist") then strTmpMetaSresults = strTmpMetaSresults & "whitelist /, "
  if instr(strHTTP_MetaResponse,"alternativeid" & chr(34) & ":" & chr(34) & "http") then 
  strTmpMetaSresults = strTmpMetaSresults & "http" & getdata(strHTTP_MetaResponse, chr(34),"alternativeid" & chr(34) & ":" & chr(34) & "http") &  " \, "
  end if
  if len(strHTTP_MetaResponse) <> 0 then
    strTmpIPgeoInfo = getdata(strHTTP_MetaResponse, chr(34), "country_name" & chr(34) & ":" & Chr(34)) 
    if strTmpIPgeoInfo <> "" then 
      strTmpMetaSresults = strTmpMetaSresults & "Country Name: " & strTmpIPgeoInfo & ", "
      strTmpCNlineE = "|" & strTmpIPgeoInfo
    else
      strTmpCNlineE = "|"
    end if
    strTmpIPgeoInfo = getdata(strHTTP_MetaResponse, chr(34), "country_code" & chr(34) & ":" & Chr(34))
    if strTmpIPgeoInfo <> "" then 
      strTmpMetaSresults = strTmpMetaSresults & "Country Code: " &  strTmpIPgeoInfo & ", "
      strTmpCClineE = "|" & strTmpIPgeoInfo
    else
      strTmpCClineE = "|"
    end if
    strTmpIPgeoInfo = getdata(strHTTP_MetaResponse, chr(34), "region_name" & chr(34) & ":" & Chr(34))
    if strTmpIPgeoInfo <> "" then 
      strTmpMetaSresults = strTmpMetaSresults & "Region Name: " &  strTmpIPgeoInfo & ", "
      strTmpRNlineE = "|" & strTmpIPgeoInfo
    else
      strTmpRNlineE = "|"  
    end if
    strTmpIPgeoInfo = getdata(strHTTP_MetaResponse, chr(34), "region_code" & chr(34) & ":" & Chr(34))
    if strTmpIPgeoInfo <> "" then 
      strTmpMetaSresults = strTmpMetaSresults & "Region Code: " &  strTmpIPgeoInfo & ", "
      strTmpRClineE = "|" & strTmpIPgeoInfo
    else
      strTmpRClineE = "|"
    end if
    strTmpIPgeoInfo = getdata(strHTTP_MetaResponse, chr(34), "city" & chr(34) & ":" & Chr(34))
    if strTmpIPgeoInfo <> "" then 
      strTmpMetaSresults = strTmpMetaSresults & "City Name: " &  strTmpIPgeoInfo
      strTmpCITlineE = "|" & strTmpIPgeoInfo
    else
       strTmpCITlineE = "|"
    end if
  else
    if enableFreeGeoIP = True then strTmpMetaSresults = SubmitGIP(strMSfilehash)
  end if
  CheckMetaScan = strTmpMetaSresults  
  
else
  if BoolDebugTrace = True then logdata strDebugPath & "\Metascan" & "_debug" & ".txt", strMSfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog

  if instr(lcase(strHTTP_MetaResponse), chr(34) & ":" & chr(34) & "not found" & chr(34) & "}") then
    'never seen
    CheckMetaScan = "Metadefender has never scanned this file hash"
  elseif instr(strHTTP_MetaResponse, "scan_all_result_a" & chr(34) & ":" & chr(34) & "Clean") then
    'no detections
    CheckMetaScan = "No Metadefender detections"
    logdata strMetaReportsPath & "\Metascan_" & strMSfilehash & ".txt", strMSfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog
  elseif strHTTP_MetaResponse <> "" then
   'detections
   arrayMSPositivDetect = split(strHTTP_MetaResponse, "scan_result_i" & Chr(34) & ":1")   
   intMSPositiveDetectionCount = ubound(arrayMSPositivDetect)
   strTmpMSOlineE = cstr(intMSPositiveDetectionCount)
   if intMSPositiveDetectionCount = 1 then
    CheckMetaScan = "Metadefender has " & cstr(intMSPositiveDetectionCount) & " positive detection"
   else
    CheckMetaScan = "Metadefender has " & cstr(intMSPositiveDetectionCount) & " positive detections"
   end if

   logdata strMetaReportsPath & "\Metascan_" & strMSfilehash & ".txt", strMSfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog
  end if 
end if
Set objHTTP_MetaScan = Nothing
End Function


Function IsHash(TestString)
Dim sTemp
Dim iLen
Dim iCtr
Dim sChar

sTemp = TestString
iLen = Len(sTemp)
If iLen > 31 Then 'md5 length is 32
	For iCtr = 1 To iLen
		sChar = Mid(sTemp, iCtr, 1)
		if isnumeric(sChar) or "a"= lcase(sChar) or "b"= lcase(sChar) or "c"= lcase(sChar) or "d"= lcase(sChar) or "e"= lcase(sChar) or "f"= lcase(sChar)  then
		  'allowed characters for hash (hex)
		else
		  IsHash = False
		  exit function
		end if
	Next

IsHash = True
else
  IsHash = False
End If    
End Function


Function encrypt(StrText, key) 
  Dim lenKey, KeyPos, LenStr, x, Newstr 
   
  Newstr = "" 
  lenKey = Len(key) 
  KeyPos = 1 
  LenStr = Len(StrText) 
  StrTmpText = StrReverse(StrText) 
  For x = 1 To LenStr 
       Newstr = Newstr & chr(asc(Mid(StrTmpText,x,1)) + Asc(Mid(key,KeyPos,1))) 
       KeyPos = keypos+1 
       If KeyPos > lenKey Then KeyPos = 1 
  Next 
  encrypt = Newstr 
 End Function 

 
Function Decrypt(StrText,key) 
  Dim lenKey, KeyPos, LenStr, x, Newstr 
   
  Newstr = "" 
  lenKey = Len(key) 
  KeyPos = 1 
  LenStr = Len(StrText) 
   
  StrText=StrReverse(StrText) 
  For x = LenStr To 1 Step -1 
       on error resume next
       Newstr = Newstr & chr(asc(Mid(StrText,x,1)) - Asc(Mid(key,KeyPos,1))) 
       if err.number <> 0 then
        msgbox "error with char " & Chr(34) & asc(Mid(StrText,x,1)) - Asc(Mid(key,KeyPos,1)) & Chr(34) & " At position " & KeyPos & vbcrlf & Mid(StrText,x,1) & Mid(key,KeyPos,1) & vbcrlf & asc(Mid(StrText,x,1)) & asc(Mid(key,KeyPos,1))
        wscript.quit(011)
       end if
       on error goto 0
       KeyPos = KeyPos+1 
       If KeyPos > lenKey Then KeyPos = 1 
       Next 
       Newstr=StrReverse(Newstr) 
       Decrypt = Newstr 
End Function 
 

Function Process_MetaScanIP_Data 
Dim strTmpMetaSassessments
DIm strTmpMetaSURLs
Dim strTmpMetaIPinfo
Dim StrMetaScanIPDetails
if instr(strTmpReturnedMetaScanIPData, ", ") then
  arrayTmpMetaScanIPResults = split(strTmpReturnedMetaScanIPData, ", ")
  For each item in arrayTmpMetaScanIPResults
    if instr(item, " /") then'Assessment returned
    strTmpMetaSassessments = strTmpMetaSassessments & replace(item, " /", "") & vbcrlf
    elseif instr(item, " \") then'Reference URL returned
    strTmpMetaSURLs = strTmpMetaSURLs & replace(replace(item, " \", ""), "\/","/")  & vbcrlf
    elseif item  <> "" then
      strTmpMetaIPinfo = strTmpMetaIPinfo & item  & vbcrlf
    end if
  next
end if
      
      if strTmpMetaSassessments <> "" then 
        StrMetaScanIPDetails = "Metadefender Online Assessment:" & vbcrlf & strTmpMetaSassessments & vbcrlf
        strTmpMetaSassessments = strTmpMetaSassessments & replace(item, vbcrlf, "/") 
        strTmpMSOlineE = "|" & strTmpMetaSassessments & strTmpMetaSURLs
      else  
        strTmpMSOlineE = "|"
      end if
      if strTmpMetaSURLs <> "" then StrMetaScanIPDetails = StrMetaScanIPDetails & "Metadefender Online Reference URLs:" & vbcrlf & strTmpMetaSURLs & vbcrlf
      if strTmpMetaIPinfo <> "" then StrMetaScanIPDetails = StrMetaScanIPDetails & "IP Geographical Information:" & vbcrlf & strTmpMetaIPinfo

        Process_MetaScanIP_Data = StrMetaScanIPDetails
 
 end function
 
 
Function SubmitThreatGRID(strSThreatGRIDHash)
Dim strReturnThreatGRIDResults
strReturnThreatGRIDResults = ""
strReturnThreatGRIDResults = CheckThreatGRID(strSThreatGRIDHash)
if strReturnThreatGRIDResults = "error" then
  intMScount = 0
  do while strReturnThreatGRIDResults = "error" and intMScount > 4
    strReturnThreatGRIDResults = CheckThreatGRID(strSThreatGRIDHash)
    intMScount = intMScount +1
    wscript.sleep 100
     if BoolDebugTrace = True then LogData strDebugPath & "\ThreatGRID" & "_debug" & ".txt", "loop " & strTGfilehash & vbtab & strReturnThreatGRIDResults,BoolEchoLog
  loop
end if
if strReturnThreatGRIDResults = "error" then
  SubmitThreatGRID = "ThreatGRID won't give results back"
  logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " ThreatGRID failed to return results four times in a row. ",False 
  intTGerrorCount = intTGerrorCount +1
  if intTGerrorCount > 4 then
    BoolUseThreatGRID = False
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " ThreatGRID failed to return results four queries four times. Disabling ThreatGRID ",False 
  end if
else
  SubmitThreatGRID = strReturnThreatGRIDResults
end if
end function


Function CheckThreatGRID(strTGfilehash)
Dim objHTTP_ThreatGRID
Dim strHTTP_MetaResponse
Dim strTGQueryString
Set objHTTP_ThreatGRID = CreateObject("MSXML2.ServerXMLHTTP")
strHTTP_MetaResponse = ""

if IsHash(strTGfilehash) then'grab file hash
          if len(strTGfilehash) = 32 then 
            strHashType = "md5"
          elseif len(strTGfilehash) = 40 then 'Hash provided is SHA1
            strHashType = "sha1"
          elseif len(strTGfilehash) = 64 then 'Hash provided is SHA256
            strHashType = "sha256"            
          end if
          strTGQueryString = "/samples"
elseif isIPaddress(strTGfilehash) then
  strHashType = "ip"
  strTGQueryString = "/samples/search"
elseif instr(strTGfilehash,"/") = 0 then
  strHashType = "domain"
  strTGQueryString = "/samples/search"  
elseif instr(strTGfilehash,"/") = 0 then
  strHashType = "url"
  strTGQueryString = "/samples/search"    
end if 
BoolPost_ThreatGRID = False
if BoolPost_ThreatGRID = true then
  
  objHTTP_ThreatGRID.open "POST", "https://sandcastle.threatgrid.com:443/api/v2/", False
  objHTTP_ThreatGRID.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
  objHTTP_ThreatGRID.setRequestHeader "api_key", strTGAPIkey

  objHTTP_ThreatGRID.send "hash=" & strTGfilehash
else
 
  if ishash(strTGfilehash) and BoolDisableCacheLookup = false then
    strHTTP_MetaResponse = CacheLookup("", "\tg\", strTGfilehash, intHashCacheThreashold)
  end if
  if strHTTP_MetaResponse = "" then
    objHTTP_ThreatGRID.open "GET", "https://panacea.threatgrid.com:443/api/v2" & strTGQueryString & "?api_key=" & strTGAPIkey & "&" & "limit=" & intTGpageLimit & "&" & strHashType & "=" & strTGfilehash, False

    on error resume next
    objHTTP_ThreatGRID.send
    
    if err.number = "-2147012894" then
      'msgbox "Time out"
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " ThreatGRID lookup for " & strTGfilehash & " failed with HTTP error. - " & err.description,False 
      CheckThreatGRID = "error"
      on error goto 0
      exit function
    elseif err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " ThreatGRID lookup for " & strTGfilehash & " failed with HTTP error. - " & err.description,False 
      on error goto 0
      exit function
    end if
    strHTTP_MetaResponse = objHTTP_ThreatGRID.responseText
    if ishash(strTGfilehash) and BoolDisableCaching = False then CacheLookup strHTTP_MetaResponse, "\tg\", strTGfilehash, intHashCacheThreashold
  end if 
end if


if instr(strHTTP_MetaResponse, "Unauthorized API request.") then
  logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " invalid credentials used to access ThreatGRID API. ThreatGRID lookup disabled",boolEchoError 
  CheckThreatGRID = "Credential Error Accessing ThreatGRID"
  BoolUseThreatGRID = False
elseif instr(strHTTP_MetaResponse, "Unknown API call") then
  logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Unknown API call. ThreatGRID lookup disabled",boolEchoError 
  BoolUseThreatGRID = False
  CheckThreatGRID = "Unknown API call when Accessing ThreatGRID"  
else
  
  if BoolDebugTrace = True then LogData strDebugPath & "\ThreatGRID" & "_debug" & ".txt", strTGfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog

  if instr(strHTTP_MetaResponse, chr(34) & "current_item_count" & chr(34) & ":0," & chr(34)) then
    'never seen
    CheckThreatGRID = "ThreatGRID has never seen this file hash"
  else
   'exists
   if IsHash(strTGfilehash) then'grab file hash
      CheckThreatGRID = "ThreatGRID has seen this file"
    elseif isIPaddress(strTGfilehash) then
      CheckThreatGRID = "ThreatGRID has samples associated with IP address " & strTGfilehash
   end if
   ' if BoolDebugTrace = True then LogData strDebugPath & "\ThreatGRID_" & strTGfilehash & ".txt", strTGfilehash & vbtab & strHTTP_MetaResponse,BoolEchoLog
  end if 
end if
Set objHTTP_ThreatGRID = Nothing
End Function



Function RBL_Lookup(strIP, strRBL)
Dim strRBLL_return
Dim strDNSServer
Dim strIPorDomain
Set sh_rbl = WScript.CreateObject("WScript.Shell")
Set fso_rbl = CreateObject("Scripting.FileSystemObject")

strDNSServer = ""
if instr(strRBL, " ") then
  strDNSServer = right(strRBL, len(strRBL) - instrRev(strRBL, " "))
  'if instr(strDNSServer, " ") then msgbox strDNSServer
  strRBL = left(strRBL, instr(strRBL, " ") -1)
end if
if isIPaddress(strIP) then
  TempReverseIP = strIP
   TempReverseIP = reverseIP(TempReverseIP) & strRBL
   strIPorDomain = "IP"
else
  TempReverseIP = strIP & strRBL'domain
  strIPorDomain = "domain"
end if
CurrentDirectory = GetFilePath(wscript.ScriptFullName)

ExecQuery = "cmd.exe /c nslookup " & TempReverseIP & " " & strDNSServer & ">" & chr(34) & strCachePath & "\rbl.txt" & chr(34)   
ErrRtn = sh_rbl.run (ExecQuery,0 ,True)

set readfilePath = fso_rbl.OpenTextFile(strCachePath & "\rbl.txt", 1, false)
if not readfilePath.AtEndOfStream then dataresults = readfilepath.readall
readfilePath.close
set readfilePath =  Nothing
strRBLL_return = ""
if instr(dataresults, "127.0.0.2") <> 0 Then
  strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
end if

if instr(strRBL, ".zen.spamhaus.org") > 0 then
  '127.0.0.2 		Direct UBE sources, spam operations & spam services
  if instr(dataresults, "127.0.0.2") <> 0 then _
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as Direct UBE sources, spam operations & spam services" & vbcrlf

  '127.0.0.3 		Direct snowshoe spam sources detected via automation
  if instr(dataresults, "127.0.0.3") <> 0 then _
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as Direct snowshoe spam sources detected via automation" & vbcrlf
  '127.0.0.4-7 		CBL (3rd party exploits such as proxies, trojans, etc.)
  if instr(dataresults, "127.0.0.4") <> 0 or instr(dataresults, "127.0.0.5") <> 0 or instr(dataresults, "127.0.0.6") <> 0 or instr(dataresults, "127.0.0.7") <> 0 or instr(dataresults, "127.0.0.8") <> 0 then _ 
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as 3rd party exploits such as proxies, trojans, etc." & vbcrlf
  '127.0.0.10-11 		End-user Non-MTA IP addresses set by ISP outbound mail policy
  if instr(dataresults, "127.0.0.10") <> 0 or instr(dataresults, "127.0.0.11") <> 0 then _
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as End-user Non-MTA IP addresses set by ISP outbound mail policy" & vbcrlf
elseif strRBL = ".dbl.spamhaus.org" then
'Return Codes 	Data Source
'127.0.1.2 	spam domain
'127.0.1.4 	phish domain
'127.0.1.5 	malware domain
'127.0.1.6 	botnet C&C domain
'127.0.1.102 	abused legit spam
'127.0.1.103 	abused spammed redirector domain
'127.0.1.104 	abused legit phish
'127.0.1.105 	abused legit malware
'127.0.1.106 	abused legit botnet C&C
'127.0.1.255 	IP queries prohibited!
  if instr(dataresults, "127.0.1.2") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as a spam domain" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.4") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as a phish domain" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.5") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as a malware domain" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.6") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as a botnet C&C domain" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.102") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as abused legit spam" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.103") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as abused spammed redirector domain" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.104") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as abused legit phish" & vbcrlf
  end if
  if instr(dataresults, "127.0.1.105") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as abused legit malware" & vbcrlf
  end if  
  if instr(dataresults, "127.0.1.106") <> 0 then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & " as abused legit botnet C&C" & vbcrlf
  end if   


elseif instr(strRBL,".multi.uribl.com") > 0 then
	if instr(dataresults, "127.0.0.14") <> 0 or instr(dataresults, "127.0.0.2") <> 0 Then
		strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	elseif instr(dataresults, "127.0.0.4") <> 0  Then
		strRBLL_return = strRBLL_return & "Grelisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	elseif instr(dataresults, "127.0.0.8") <> 0  Then
		strRBLL_return = strRBLL_return & "Redlisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	elseif instr(dataresults, "127.0.0.1") <> 0 Then
		'queries are not working
		logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " uribl lookup failed with 127.0.0.1 response http://uribl.com/about.shtml#abuse",False 
	end if

elseif instr(strRBL,".multi.surbl.org") > 0 then 'http://www.surbl.org/guidelines

  if instr(dataresults, "127.0.0.8") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Phishing"
  elseif instr(dataresults, "127.0.0.16") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware"
  elseif instr(dataresults, "127.0.0.24") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Phishing"
	elseif instr(dataresults, "127.0.0.64") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Abuse"
  elseif instr(dataresults, "127.0.0.72") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Phishing^Abuse"	
  elseif instr(dataresults, "127.0.0.80") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Abuse"	
  elseif instr(dataresults, "127.0.0.88") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Phishing^Abuse"		
  elseif instr(dataresults, "127.0.0.126") <> 0 Then
  	strTmpSURbLineE = "test"
  elseif instr(dataresults, "127.0.0.128") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "CrackedSite"
  elseif instr(dataresults, "127.0.0.136") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Phishing^CrackedSite"	
  elseif instr(dataresults, "127.0.0.142") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^CrackedSite"	
	elseif instr(dataresults, "127.0.0.150") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Phishing^CrackedSite"	
  elseif instr(dataresults, "127.0.0.192") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Abuse^CrackedSite"		
  elseif instr(dataresults, "127.0.0.200") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Phishing^Abuse^CrackedSite"		
  elseif instr(dataresults, "127.0.0.208") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Abuse^CrackedSite"	
  elseif instr(dataresults, "127.0.0.216") <> 0 Then
    strRBLL_return = strRBLL_return & "Blacklisted " & strIPorDomain & " " & strIP & " at " & right(strRBL, len(strRBL) -1) & vbcrlf
	strTmpSURbLineE = "Malware^Phishing^Abuse^CrackedSite"	
  end if

elseif instr(strRBL, ".dnsbl.sorbs.net") > 0 then
	if instr(dataresults, "127.0.0.2") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "HTTP Proxy", "^")
	end if
	if instr(dataresults, "127.0.0.3") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "SOCKS Proxy", "^")
	end if
	if instr(dataresults, "127.0.0.4") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "MISC Proxy", "^")
	end if
	if instr(dataresults, "127.0.0.5") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Open SMTP Relay", "^")
	end if
	if instr(dataresults, "127.0.0.6") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Spam", "^")
	end if
	if instr(dataresults, "127.0.0.7") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Web", "^")
	end if
	if instr(dataresults, "127.0.0.8") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Block", "^")
	end if
	if instr(dataresults, "127.0.0.9") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Zombie", "^")
	end if
	if instr(dataresults, "127.0.0.10") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "Dynamic", "^")
	end if
	if instr(dataresults, "127.0.0.11") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "BadConf", "^")
	end if
	if instr(dataresults, "127.0.0.12") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "NoMail", "^")
	end if	
	if instr(dataresults, "127.0.0.14") > 0 Then
		strSORBSlineE = AppendValuesList(strSORBSlineE, "NoServer", "^")
	end if	
end if 
  
  RBL_Lookup = strRBLL_return
End Function


Function ReverseIP (ip)
if isIpv6(ip) =  True then 
	'ipV6 not supported yet here
	ReverseIP = ip
	exit function
end if
reverseip = "." & left(ip,instr(ip,".")-1)
ip = right(ip,len(ip) - len(left(ip,instr(ip,"."))))

reverseip = "." & left(ip,instr(ip,".")-1) & reverseip
ip = right(ip,len(ip) - len(left(ip,instr(ip,"."))))

reverseip = "." & left(ip,instr(ip,".")-1) & reverseip
ip = right(ip,len(ip) - len(left(ip,instr(ip,"."))))

reverseip = ip & reverseip
end function


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


Function SubmitCIF(strSCIFHash)
Dim strReturnCIFResults
strReturnCIFResults = ""
strReturnCIFResults = CheckCIF(strSCIFHash)
if strReturnCIFResults = "error" then
  intMScount = 0
  do while strReturnCIFResults = "error" and intMScount < 2
    strReturnCIFResults = CheckCIF(strSCIFHash)
	wscript.sleep 3
    intMScount = intMScount +1
  loop
end if
 
if strReturnCIFResults = "error" then
  SubmitCIF = "CIF won't give results back"
else
  if BoolCreateSpreadsheet = True and intVTListDataType = 1 and strReturnCIFResults <> "" then 'IP/domain
    SubmitCIF = strReturnCIFResults
  end if
end if
end function


Function CheckCIF(strCIFscanItem)
Dim objHTTP_CIF
Dim strHTTP_CIFResponse
Dim strTGQueryString
Dim ArrayCIFsplit
Dim strTmpAssessment
Dim strTmpDescription
Dim intConfidence
Dim DictCIFinfo: Set DictCIFinfo = CreateObject("Scripting.Dictionary")

if lcase(left(strCIFurl, 4)) <> "http" then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Invalid CIF URL provided in INI " & chr(34) & strCIFurl & chr(34) & ". Please update the vttl.ini file for the CIF_URL=URLvalue",False
	exit function
end if
Set objHTTP_CIF = CreateObject("MSXML2.ServerXMLHTTP")
strHTTP_CIFResponse = ""

strCIFqueryString = "q"
BoolPost_CIF = False
if BoolPost_CIF = true then
  
  objHTTP_CIF.open "POST", strCIFurl, False
  objHTTP_CIF.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
  objHTTP_CIF.setRequestHeader "Authorization: Token token", strCIF_APIkey

  objHTTP_CIF.send 
else
 
  objHTTP_CIF.open "GET", strCIFurl & "?" & strCIFqueryString & "=" & strCIFscanItem & "&limit=100&nolog=" & intCIFlog & "&confidence=" & strCIFconfidence, False
  objHTTP_CIF.setRequestHeader "Accept", "application/vnd.cif.v2+json"
  objHTTP_CIF.setRequestHeader "Authorization", "Token token=" & strCIF_APIkey
  
  on error resume next
  objHTTP_CIF.send 
  
  '2147012889 - The Server name or address could not be resolved
  if err.number = "-2147012894" or err.number = "-2147012744" or err.number = "2147012889" then
    'msgbox "Time out"
    logdata strDebugPath & "\VTTL_Error.log", Date & " " & Time & " CIF lookup for " & strCIFscanItem & " failed with HTTP error. - " & err.description,False 
    CheckCIF = "error"
    on error goto 0
    exit function
  elseif err.number <> 0 then
    logdata strDebugPath & "\VTTL_Error.log", Date & " " & Time & " CIF lookup for " & strCIFscanItem & " failed with HTTP error. - " & err.description,False 
    'msgbox  " CIF lookup failed with unknown error. - " & err.number & err.description
	CheckCIF = "error"
    on error goto 0
    exit function
  end if
  
end if
strHTTP_CIFResponse = objHTTP_CIF.responseText
logdata strDebugPath & "\CIF_Response.log", Date & " " & Time & " " & strHTTP_CIFResponse ,False 

if instr(strHTTP_CIFResponse, "unauthorized") then
  wscript.echo "invalid credentials used for CIF"
  CheckCIF = "Credential Error Accessing CIF"
elseif instr(strHTTP_CIFResponse, "Unknown API call") then
  wscript.echo "Unknown API call"
  CheckCIF = "Unknown API call when Accessing CIF"  
elseif instr(strHTTP_CIFResponse, "failraptor") or objHTTP_CIF.status  <> 200 then
  wscript.echo "Failed API call when Accessing CIF"
  CheckCIF = "Failed API call when Accessing CIF"
elseif instr(strHTTP_CIFResponse, chr(34) & "tags" & chr(34) & ":[") then
  ArrayCIFsplit = split(strHTTP_CIFResponse, chr(34) & "tags" & chr(34) & ":[")
  boolskippedFirst = False
  for each strTmpCIFsplit in ArrayCIFsplit
    if boolskippedFirst = True or right(strTmpCIFsplit,1) = "{" then
      strTmpAssessment = getdata(strTmpCIFsplit, chr(34),chr(34))
    end if
    if boolskippedFirst = False then boolskippedFirst = True
    
    if strTmpAssessment <>  ""  then  
        if not DictCIFinfo.Exists(strTmpAssessment) then _
          DictCIFinfo.Add strTmpAssessment, 1

    end if
  next
  For Each Item In DictCIFinfo
  if strTmpCIF_Sresults = "" then 
  
    strTmpCIF_Sresults = Item
  else
    strTmpCIF_Sresults = strTmpCIF_Sresults & "^" & Item
  end if
next

  if BoolDebugTrace = True then LogData strDebugPath & "\CIF" & "out_debug" & ".txt", strTmpCIF_Sresults,BoolEchoLog
'msgbox "strTmpCIF_Sresults= " & strTmpCIF_Sresults
  CheckCIF = strTmpCIF_Sresults
elseif  strHTTP_CIFResponse <> "[]" then
	logdata strDebugPath & "\VTTL_Error.log", Date & " " & Time & " Problem parsing CIF results from lookup for " & strCIFscanItem & ". " & objHTTP_CIF.status & ": " & strHTTP_CIFResponse ,False 
end if
Set objHTTP_CIF = Nothing
End Function


Sub Write_Spreadsheet_line(strSSrow)
Dim strTmpSSlout
Dim boolQueued: boolQueued = False

'msgbox "queue :" & strtmpVendQueue
if strtmpVendQueue <> "" then 'TIA queueing - Add item to queue instead of writing out
	outQueue.Enqueue strSSrow
	lookupQueue.Enqueue strtmpVendQueue
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "lookupQueue.Enqueue " & strtmpVendQueue,BoolEchoLog 
	strtmpVendQueue = ""
	boolQueued = True
elseif BoolUseExcel = True then
  Dim intColumnCounter
  if instr(strSSrow,"|") then
    strSSrow = split(strSSrow, "|")
    for intColumnCounter = 1 to ubound(strSSrow) + 1
      on error resume next
      objExcel.Cells(intWriteRowCounter, intColumnCounter).Value = strSSrow(intColumnCounter -1)
      if err.number <>0 then
          StrQuestion = msgbox("Error writing to spreadsheet. This can happen if you accessed cell contents. Click out of any cell and choose yes. To quit choose no.",4,"Question")
        if StrQuestion = 7 then'no
          wscript.quit(589)
        elseif StrQuestion <> 6 then  
          msgbox "invalid response"
        end if
        objExcel.Cells(intWriteRowCounter, intColumnCounter).Value = strSSrow(intColumnCounter -1)
      end if
      on error goto 0
    next
  elseif strSSrow = "" then
	'do nothing. This is to drop out the TIA queue
  else
      objExcel.Cells(intWriteRowCounter, 1).Value = strSSrow
  end if
  intWriteRowCounter = intWriteRowCounter + 1
else
  strTmpSSlout = replace(strSSrow, chr(34), "") 'remove existing quotes as it can break CSV output
  strTmpSSlout = replace(strTmpSSlout, "|",chr(34) & "," & Chr(34))
  strTmpSSlout = chr(34) & strTmpSSlout & chr(34)
  logdata strSSfilePath, strTmpSSlout, False
end if

'TIA dequeueing
if boolEnableTIAqueue = False then exit sub
if outQueue.Count > 0 and lookupQueue.Count > 0 then
	strTmpTIAItems = lookupQueue.Peek
	strTmpRowOut = outQueue.Peek
	objShellComplete.popup "lookupQueue.Count = " & lookupQueue.Count,10
	if boolQueued = True and lookupQueue.Count = 1 then 
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "already looked this one up recently: " & strTmpTIAItems,BoolEchoLog 
		boolQueued = False 'reset so we don't get stuck in a loop
		exit sub 'already looked this one up recently
		
	end if
	boolSuccess = True
	if instr(strTmpTIAItems, "õ") = 0 then 'not expected so dump row
		lookupQueue.dequeue
		outQueue.Dequeue
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "Invalid strTmpTIAItems: " & strTmpTIAItems & " strtmpVendQueue=" & strtmpVendQueue,BoolEchoLog 
		Write_Spreadsheet_line strTmpRowOut
		exit sub
	end if
	 if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strTmpTIAItems: " & strTmpTIAItems ,BoolEchoLog
	arrayTmpTIAItems = split(strTmpTIAItems, "õ")
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "ubound(arrayTmpTIAItems): " & ubound(arrayTmpTIAItems) ,BoolEchoLog
	for each strTmpTIAItem in arrayTmpTIAItems
		if instr(strTmpTIAItem, "|") > 0 then
			arrayTIAitems = split(strTmpTIAItem, "|")
			strTIAresult = Encyclopdia_Cache(arrayTIAitems(0),arrayTIAitems(1))'returns vendor name if in queue 
			if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strTIAresult <> arrayTIAitems(0): " & strTIAresult & "  <> " & arrayTIAitems(0) ,BoolEchoLog 
			if strTIAresult <> arrayTIAitems(0) then 
				if strTIAresult <> "" then 
					strTmpRowOut = replace(strTmpRowOut, arrayTIAitems(0), arrayTIAitems(1))
				else
					strTmpRowOut = replace(strTmpRowOut, arrayTIAitems(0), "")
				end if
			else   'Item is still in the TIA server's queue
				boolSuccess = False
				objShellComplete.popup "Item still in queue: " & strTmpTIAItem, 10
				if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", outQueue.count & " items in the queue. Item still in queue: " & strTmpTIAItem,False 
				
				if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", outQueue.count & " items in the queue. Item still in queue: " & strTmpTIAItem,BoolEchoLog 
				boolPendingTIAItems = True
				exit sub 'no need to keep going if we can't complete the whole row
			end if
		end if
	next
	if boolSuccess = True then
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "Dequeued items: " & strTmpTIAItems,False 
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "boolSuccess = True: " & strTmpRowOut & " strtmpVendQueue=" & strtmpVendQueue,BoolEchoLog 
		lookupQueue.dequeue
		outQueue.Dequeue
		Write_Spreadsheet_line strTmpRowOut
	end if
end if
if outQueue.Count = 0 then boolPendingTIAItems = False
end sub


Function SubmitGIP(strSGIPaddr)
Dim strReturnGIPResults
strReturnGIPResults = ""
strReturnGIPResults = CheckGIP(strSGIPaddr)
if strReturnGIPResults = "error" then
  intMScount = 0
  do while strReturnGIPResults = "error" and intMScount < 5
    strReturnGIPResults = CheckGIP(strSGIPaddr)
    intMScount = intMScount +1
  loop
end if
if strReturnGIPResults = "error" then
  SubmitGIP = "GIP won't give results back"
else
  SubmitGIP = strReturnGIPResults
end if
end function


Function CheckGIP(strGIPaddress)
Dim objHTTP_GIP
Dim strHTTP_GIPResponse
Dim strTGQueryString
Dim strTmpAssessment
Dim strTmpDescription
Dim DictGIPinfo: Set DictGIPinfo = CreateObject("Scripting.Dictionary")
Set objHTTP_GIP = CreateObject("MSXML2.ServerXMLHTTP")
strHTTP_GIPResponse = ""

  objHTTP_GIP.open "GET", "https://freegeoip.app/xml/" & strGIPaddress, False

  on error resume next
  objHTTP_GIP.send 
  
  if objHTTP_GIP.status = 403 then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " GeoIP lookup failed for " & strGIPaddress & " with 403 HTTP error. - " & err.description,False 
  elseif err.number = "-2147012894" then
    'msgbox "Time out"
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " GeoIP lookup failed for " & strGIPaddress & " with HTTP error. - " & err.description,False 
    CheckGIP = "error"
    on error goto 0
    exit function
  elseif err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " GeoIP lookup failed for " & strGIPaddress & " with HTTP error. - " & err.description,False 
    on error goto 0
  end if
on error resume next
strHTTP_GIPResponse = objHTTP_GIP.responseText

  Dim objStreamConvert
  Set objStreamConvert = CreateObject("ADODB.Stream")

 'FreeGeoIP gives data in unicode which messes up file logging. This code converts to ASCII.
objStreamConvert.CharSet = "us-ascii"  
objStreamConvert.Open
objStreamConvert.WriteText strHTTP_GIPResponse
objStreamConvert.position = 0
strHTTP_GIPResponse = objStreamConvert.ReadText
Set objStreamConvert = Nothing

if err.number <>0 then exit function
on error goto 0
if BoolDebugTrace = True then logdata strDebugPath & "\freegeoip" & "_debug" & ".txt", strGIPaddress & " - " & strHTTP_GIPResponse,BoolEchoLog
if instr(strHTTP_GIPResponse, "Unauthorized API request.") then
  wscript.echo "invalid credentials for GeoIP lookup"
  CheckGIP = "Credential Error Accessing GIP"
elseif instr(strHTTP_GIPResponse, "Unknown API call") then
  wscript.echo "Unknown API call"
  CheckGIP = "Unknown API call when Accessing GIP"  
elseif instr(strHTTP_GIPResponse, ">" & strGIPaddress &"<") then
    strTmpIPgeoInfo = getdata(strHTTP_GIPResponse, "<", "CountryName>") 
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "Country Name: " & strTmpIPgeoInfo & ", "
    strTmpCNlineE = "|" & strTmpIPgeoInfo
  else
    strTmpCNlineE = "|"
  end if
  strTmpIPgeoInfo = getdata(strHTTP_GIPResponse,"<", "CountryCode>")
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "Country Code: " &  strTmpIPgeoInfo & ", "
    strTmpCClineE = "|" & strTmpIPgeoInfo
  else
    strTmpCClineE = "|"
  end if
  strTmpIPgeoInfo = getdata(strHTTP_GIPResponse,"<", "RegionName>")
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "Region Name: " &  strTmpIPgeoInfo & ", "
    strTmpRNlineE = "|" & strTmpIPgeoInfo
  else
    strTmpRNlineE = "|"  
  end if
  strTmpIPgeoInfo = getdata(strHTTP_GIPResponse,"<", "RegionCode>")
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "Region Code: " &  strTmpIPgeoInfo & ", "
    strTmpRClineE = "|" & strTmpIPgeoInfo
  else
    strTmpRClineE = "|"
  end if
  strTmpIPgeoInfo = getdata(strHTTP_GIPResponse,"<", "City>")
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "City Name: " &  strTmpIPgeoInfo & ", "
    strTmpCITlineE = "|" & strTmpIPgeoInfo
  else
     strTmpCITlineE = "|"
  end if
    strTmpIPgeoInfo = getdata(strHTTP_GIPResponse,"<", "ZipCode>")
  if strTmpIPgeoInfo <> "" then 
    strTmpIPgeoIPreturn = strTmpIPgeoIPreturn & "Zip Code: " &  strTmpIPgeoInfo
  end if
  
  if strTmpCNlineE = "|" and strTmpCClineE = "|" Then
	If instr(strHTTP_GIPResponse, "<Latitude>35</Latitude>") > 0 and _
	instr(strHTTP_GIPResponse, "<Longitude>105</Longitude") > 0 then
		strTmpCNlineE = "United States"
		strTmpCClineE = "US"
	elseif instr(strHTTP_GIPResponse, "<Latitude>47</Latitude>") > 0 and _
		instr(strHTTP_GIPResponse, "<Longitude>8</Longitude") > 0 then
			strTmpCNlineE = "Europe"
			strTmpCClineE = "EU"
	end if
  end if
  CheckGIP = strTmpIPgeoIPreturn
else
  logdata strDebugPath & "\VTTL_Error.log", Date & " " & Time & " GeoIP lookup failed with no valid data returned",False 
end if
Set objHTTP_GIP = Nothing
End Function


Function nslookup_Return(strServerName)
Set sh = WScript.CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
  CurrentDirectory = GetFilePath(wscript.ScriptFullName)

  ExecQuery = "nslookup " & strServerName  & " | findstr /C:" & chr(34) & "Name:" & chr(34) & ">" & chr(34) & strCachePath & "\ns.txt" & chr(34)   

                ErrRtn = sh.run ("%comspec% /c " &  ExecQuery,0 ,True)

               Set ObjNSfile = FSO.GetFile(strCachePath & "\ns.txt")
if ObjNSfile.Size <> 0 then
               set readfilePath = fso.OpenTextFile(strCachePath & "\ns.txt", 1, false)

  dataresults = readfilepath.readall

  readfilePath.close
  set readfilePath =  Nothing
  if instr(dataresults, "Name:") then dataresults = replace (dataresults,"Name:    ","")
  nslookup_Return = left(dataresults,instr(dataresults,vbcrlf) -1)

else
'msgbox "error launching command"
end if
Set ObjNSfile = Nothing
Set sh = Nothing
Set fso = Nothing
End Function



Function GetIPContact(strIPcontact)
Dim strReturnContactResults

if instr(strIPcontact,".") > 0 or instr(strIPcontact,":") > 0 then
  if isIPv6(strIPcontact) = True then 'quick fix for IPv6 need to fix this
	strIPcontact = lcase(strIPcontact) 'force hex to lowercase
	if IpV6RIPE(strIPcontact) = True then
		GetIPContact = Checkripe(strIPcontact, True)
	end if
	GetIPContact = CheckARIN(strIPcontact)
	exit function
  end if
  
  if DictArin.exists(left(strIPcontact, instr(strIPcontact,".") -1))  then 
    strReturnContactResults = CheckARIN(strIPcontact)
  elseif Dictripe.exists(left(strIPcontact, instr(strIPcontact,".") -1)) then
    strReturnContactResults = Checkripe(strIPcontact, False)
  else
    strReturnContactResults = WhoIsIP_Lookup(strIPcontact)
  end if

  if strReturnGIPResults = "error" then
    intMScount = 0
    do while strReturnGIPResults = "error" and intMScount > 5
      wscript.sleep 1000
      if DictArin.exists(left(strIPcontact, instr(strIPcontact,".") -1)) Then
        strReturnContactResults = CheckARIN(strIPcontact)
      elseif Dictripe.exists(left(strIPcontact, instr(strIPcontact,".") -1)) then
        strReturnContactResults = Checkripe(strIPcontact, False)
      else
        strReturnContactResults = WhoIsIP_Lookup(strIPcontact)
      end if
      intMScount = intMScount +1
    loop
  end if
end if
GetIPContact = strReturnContactResults
end function


Function CleanupWhoisData(strWhoisDirty)
Dim strWhoisCleanReturn
strWhoisCleanReturn = strWhoisDirty

if instr(strWhoisCleanReturn,"                            ") then _
 strWhoisCleanReturn = replace(strWhoisCleanReturn,"                            ","")
if instr(strWhoisCleanReturn,"                         ") then _
 strWhoisCleanReturn = replace(strWhoisCleanReturn,"                         ","")

'remove space from begenning and end
strWhoisCleanReturn = RemoveTLS(strWhoisCleanReturn) 
CleanupWhoisData = strWhoisCleanReturn
end function


Function isHexInRange(ProvidedValue, BottomRange, UpperRange) 'used to check IPv6 range
CompareVal1 = CLng("&H" & BottomRange)
compareVal2 = CLng("&H" & UpperRange)
ProvidedHexValue = CLng("&H" & ProvidedValue)
if ProvidedHexValue >= CompareVal1 and ProvidedHexValue <= compareVal2 then
  isHexInRange = True
else
  isHexInRange = False
end if
end function


Function IpV6RIPE(strIPv6Address)
boolRIPEreturn = False
if instr(strIPv6Address, ":") then
  arrayHextet = split(strIPv6Address, ":")
  select case arrayHextet(0)
    case "2001"
      boolRIPEreturn = isHexInRange (arrayHextet(1), "0600", "09ff")
      'msgbox boolRIPEreturn
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "0a00", "0bff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "1400", "17ff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "1a00", "3bff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "4000", "41ff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "4600", "47ff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "4a00", "4dff")
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "5000", "5fff")
    Case "2003"
      if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "0000", "3fff")
    Case else
      if boolRIPEreturn = false and boolRIPEreturn = isHexInRange (arrayHextet(0), "2a00", "2a0f") then
        if boolRIPEreturn = false then boolRIPEreturn = isHexInRange (arrayHextet(1), "0000", "ffff")   
      end if
  end select
end if
IpV6RIPE = boolRIPEreturn
end function

Function CheckIpV6ARIN(strIPv6Address)
boolARINReturn = False
if instr(strIPv6Address, ":") then
  arrayHextet = split(strIPv6Address, ":")
    select case arrayHextet(0)
      case "2001"
        boolARINReturn = isHexInRange (arrayHextet(1), "0400", "05ff")
        if boolARINReturn = false then boolARINReturn = isHexInRange (arrayHextet(1), "1800", "19ff")
        if boolARINReturn = false then boolARINReturn = isHexInRange (arrayHextet(1), "4800", "49ff")
      case "2610"
        boolARINReturn = isHexInRange (arrayHextet(1), "0000", "01ff")
      case "2620"
        boolARINReturn = isHexInRange (arrayHextet(1), "0000", "01ff")		
      case else '2600:0000::/12
        boolARINReturn = isHexInRange (arrayHextet(0), "2600", "260f")
		
    end select
end if
CheckIpV6ARIN = boolARINReturn
end function


Function CheckARIN(strIPwhoIS) 'v 1.2
Dim strWISresponse
Dim strTmpCARINreturn
Dim IpVchar: IpVchar = "."
'https://www.arin.net/resources/whoisrws/whois_api.html
If boolUseARIN = False then exit function	
if isIPv6(strIPwhoIS) = True Then 
	if CheckIpV6ARIN(strIPwhoIS) = False then exit function 'if not in ARIN range exit
	IpVchar = ":" 'IPv6 will cause error with left statement below
end if

if DictArin.exists(left(strIPwhoIS, instr(strIPwhoIS,IpVchar) -1)) or isIPv6(strIPwhoIS) = True then 
  Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
    objHTTP.open "GET", "http://whois.arin.net/rest/ip/" & strIPwhoIS, False
  on error resume next
      objHTTP.send strIPwhoIS
      if err.number <> 0 then 
        CheckARIN = "error"
        exit function
      end if
  on error goto 0
  strWISresponse = objHTTP.responseText
   if BoolDebugTrace = True then LogData strDebugPath & "\arin.log", strWISresponse, false
  if instr(strWISresponse, "orgRef name=" & chr(34)) then
    strTmpCARINreturn = GetData(strWISresponse, chr(34),"orgRef name=" & chr(34))
  elseif instr(strWISresponse, "customerRef name="& chr(34)) then
    strTmpCARINreturn = GetData(strWISresponse, chr(34),"customerRef name="& chr(34))
  elseif instr(strWISresponse, chr(34) & " name="& chr(34)) then
    strTmpCARINreturn = GetData(strWISresponse, chr(34),chr(34) & " name="& chr(34))   
  end if
  
  if strTmpCARINreturn = "" then
    strTmpCARINreturn = WhoIsIP_Lookup(strIPwhoIS)
  elseif strTmpCARINreturn = "RIPE Network Coordination Centre" then
    strTmpCARINreturn = Checkripe(strIPwhoIS, True)
  end if
  CheckARIN = strTmpCARINreturn

  CheckWhoISData strWISresponse
  if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "ARIN API response", false   
  Set objHTTP = Nothing
end if  
end Function


Function Checkripe(strIPwhoIS, boolRipeOveride)
Dim strWISresponse
Dim ArrayRipeResponse
Dim strTmpCRIPEreturn
dim IpVchar: IpVchar = "."
If boolUseRIPE = False then exit function
if isIPv6(strIPwhoIS) = True Then 
	if IpV6RIPE(strIPwhoIS) = False then exit function 'if not in RIPE range exit
	IpVchar = ":" 'IPv6 will cause error with left statement below
end if
if boolRipeOveride = True or Dictripe.exists(left(strIPwhoIS, instr(strIPwhoIS,IpVchar) -1)) or isIPv6(strIPwhoIS) = True then

  Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")

    objHTTP.open "GET", "http://rest.db.ripe.net/search.xml?query-string=" & strIPwhoIS, False
   
on error resume next
    objHTTP.send strIPwhoIS
    if err.number <> 0 then 
      Checkripe = "error"
      exit function
    end if
on error goto 0

  strWISresponse = objHTTP.responseText
  if instr(strWISresponse, "see http://www.iana.org." & chr(34) & "/>") > 0 and _ 
  instr(strWISresponse, "Internet Assigned Numbers Authority"&  chr(34) & "/>") > 0 then
    'not in RIPE database
    Checkripe = ""
    exit function
  end if
  if instr(strWISresponse, "<object type=" & chr(34) & "role" & chr(34) & ">") then
    ArrayRipeResponse = split(strWISresponse, "<object type=" & chr(34) & "role" & chr(34) & ">")
     if BoolDebugTrace = True then LogData strDebugPath & "\ripe.log", ArrayRipeResponse(1), false
    if instr(ArrayRipeResponse(1), "<attribute name=" & chr(34) & "role" & chr(34) & " value=" & chr(34)) then
      strTmpCRIPEreturn= GetData(ArrayRipeResponse(1), chr(34),"<attribute name=" & chr(34) & "role" & chr(34) & " value=" & chr(34))

    end if
  end if

  if strTmpCRIPEreturn = "" then
      strTmpCRIPEreturn = GetData(strWISresponse, chr(34),"<attribute name=" & chr(34) & "org-name" & chr(34) & " value=" & chr(34))
  end if
  if strTmpCRIPEreturn = "" then
      strTmpCRIPEreturn = GetData(strWISresponse, chr(34),"<attribute name=" & chr(34) & "person" & chr(34) & " value=" & chr(34))
  end if   
  Set objHTTP = Nothing
end if  
if strTmpCRIPEreturn = "" then
  strTmpCRIPEreturn = WhoIsIP_Lookup(strIPwhoIS)
end if

CheckWhoISData strWISresponse
if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "RIPE API response", false
Checkripe  = strTmpCRIPEreturn
end Function


Function WhoIsDomain_Lookup(strWhoIsIPaddress) 'sysinternals whois
Dim strWhoIsIP_return
Set sh_WhoIsIP = WScript.CreateObject("WScript.Shell")
Set fso_WhoIsIP = CreateObject("Scripting.FileSystemObject")

CurrentDirectory = GetFilePath(wscript.ScriptFullName)

ExecQuery = "whois -v " & strWhoIsIPaddress  & ">" & chr(34) & strCachePath & "\WhoIsIP.txt" & chr(34)   
if boolWhoIsDebug = True then msgbox "whois command line: " & ExecQuery
ErrRtn = sh_WhoIsIP.run ("%comspec% /c " &  ExecQuery,0 ,True)
wscript.sleep 10
set readfilePath = fso_WhoIsIP.OpenTextFile(strCachePath & "\WhoIsIP.txt", 1, false)
if not readfilePath.AtEndOfStream then dataresults = readfilepath.readall
readfilePath.close
set readfilePath =  Nothing
strWhoIsIP_return = ""
WhoIsDomain_Lookup = WhoIsDomain_Parse(dataresults)
end function


Function WhoIsDomain_Parse(dataresults) 'loose text generic whois
'check for sinkhole 
CheckWhoISData dataresults
if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "Sysinternals whois response", false

' set city, region, and country code for spreadsheet output
if strTmpCITlineE = "" or strTmpCITlineE = "|" then
	strTmpCITlineE = Getdataon(dataresults , vbcr, "\n", "Registrant City:")
	strTmpCITlineE = "|" & CleanupWhoisData(strTmpCITlineE)
end if
if strTmpRNlineE = "" or strTmpRNlineE = "|" then
	strTmpRNlineE = Getdataon(dataresults , vbcr, "\n", "Registrant State/Province:")
	strTmpRNlineE = "|" & CleanupWhoisData(strTmpRNlineE)
end if
if strTmpCClineE = "" or strTmpCClineE = "|" then
	strTmpCClineE = Getdataon(dataresults , vbcr, "\n", "Registrant Country:")
	
	if len(strTmpCClineE) > 3 and (mid(strTmpCClineE, 4, 1) = chr(34) or mid(strTmpCClineE, 3, 1) = chr(34)) then 'VirusTotal provided CC
		strTmpCClineE = left(strTmpCClineE,instr(strTmpCClineE, chr(34)) -1)
	end if
	strTmpCClineE = "|" & CleanupWhoisData(strTmpCClineE)
end if
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois Creation Date before being set: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
if strTmpWCO_CClineE = "" or strTmpWCO_CClineE = "|" or len(strTmpWCO_CClineE) < 4  then
  strTmpWCO_CClineE = Getdataon(dataresults , vbcr, "\n", "Creation Date:")
  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois Creation Date: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
  strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
  if CheckBadValues(strTmpWCO_CClineE) then 
    strTmpWCO_CClineE = Getdataon(dataresults , vbcr, "\n", "created:")
    strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
  end if 
	if CheckBadValues(strTmpWCO_CClineE) and instr(dataresults, "Created On:") then 
		strTmpWCO_CClineE = Getdataon(dataresults , vbcr, "\n", "Created On:")
	end if
	if CheckBadValues(strTmpWCO_CClineE) and instr(dataresults, "Registration Time:") then 
		strTmpWCO_CClineE = Getdataon(dataresults , vbcr, "\n", "Registration Time:")
	end if
else
  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois already set Creation Date: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
end if

MoveSSLocationEntries 'check if country code is listed as country name


strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "Registrant Organization:")

'GetDataOn(contents, ByVal EndOfStringChar, ByVal EndOfStringCharAlt, ByVal MatchString)
if CheckBadValues(strWhoIsIP_return) then _
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "Registrant Name:")
if CheckBadValues(strWhoIsIP_return) then _
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "Registrant ID:")
if CheckBadValues(strWhoIsIP_return) then _ 
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "Name:")

 'fix problem where domain name is provided for whois owner
if strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "Domain Name:") then
	strWhoIsIP_return = ""
end if

if CheckBadValues(strWhoIsIP_return) then _ 
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "organisation:")
 if CheckBadValues(strWhoIsIP_return) then _ 
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "org:") 
if CheckBadValues(strWhoIsIP_return) then _ 
 strWhoIsIP_return = Getdataon(dataresults , vbcr, "\n", "owner:")

if instr(strWhoIsIP_return, chr(34) & ",") > 0 then 'VirusTotal data scenario where no vbCr or \n
	strWhoIsIP_return = left(strWhoIsIP_return, instr(strWhoIsIP_return, chr(34) & ",") -1)
end if
strWhoIsIP_return = RemoveTLS(strWhoIsIP_return)
WhoIsDomain_Parse = strWhoIsIP_return
if len(strTmpWCO_CClineE) > 43 then strTmpWCO_CClineE = "" 'replace failure to parse entry
End function


Sub MoveSSLocationEntries
'check if country code is listed as country name
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after before moveSS: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRNlineE =" & strTmpRNlineE & "^" & "strTmpCNlineE =" & strTmpCNlineE, false
if len(strTmpRNlineE) = 3 and len(strTmpCClineE) > 3 then
  strTmpCNlineE = strTmpCClineE
  strTmpCClineE = strTmpRNlineE
  strTmpRNlineE = ""

elseif (len(strTmpRNlineE) = 1 or len(strTmpRNlineE) > 3) and len(strTmpCClineE) > 3 then
  strTmpCNlineE = strTmpCClineE
  strTmpCClineE = ""
elseif len(strTmpCNlineE) = 3 and len(strTmpCClineE) < 2 then
  strTmpCClineE = strTmpCNlineE
  strTmpCNlineE = ""
end if

strTmpCC = ucase(replace(strTmpCClineE, "|",""))
strTmpCN = ucase(replace(strTmpCNlineE, "|",""))

if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "CC|CN:" & strTmpCC & "|" & strTmpCN, false
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "CC|CN:" & DictRevCC.exists(strTmpCC) & "|" & DictCC.exists(strTmpCN) & "|" & (strTmpCC = ""), false
if strTmpCC = "" and DictCC.exists(strTmpCN) then
	strTmpCClineE = addpipe(DictCC.item(strTmpCN))
	if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "strTmpCClineE =" & "|" & DictCC.item(strTmpCN), false
elseif strTmpCN = "" and DictRevCC.exists(strTmpCC) then
	strTmpCNlineE = addpipe(DictRevCC.item(strTmpCC))
end if
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after before moveSS: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRNlineE =" & strTmpRNlineE & "^" & "strTmpCNlineE =" & strTmpCNlineE, false
end sub


Function WhoIsIP_Lookup(strWhoIsIPaddress)
'This function requires a Whois client and has only been tested with http://www.nirsoft.net/utils/whosip.html
if BooWhoIsIPLookup = True then
Dim strWhoIsIP_return
Set sh_WhoIsIP = WScript.CreateObject("WScript.Shell")
Set fso_WhoIsIP = CreateObject("Scripting.FileSystemObject")

CurrentDirectory = GetFilePath(wscript.ScriptFullName)

ExecQuery = "cmd.exe /c whosip " & strWhoIsIPaddress  & ">" & chr(34) & strCachePath & "\WhoIsIP.txt" & chr(34)   
              ErrRtn = sh_WhoIsIP.run ("%comspec% /c " &  ExecQuery,0 ,True)
              if ErrRtn <> 0 then BooWhoIsIPLookup = False
             set readfilePath = fso_WhoIsIP.OpenTextFile(strCachePath & "\WhoIsIP.txt", 1, false)
if not readfilePath.AtEndOfStream then dataresults = readfilepath.readall
readfilePath.close
set readfilePath =  Nothing
strWhoIsIP_return = ""
strWhoIsIP_return = Getdata(dataresults , vbcrlf, "Owner Name:   ")

'check for sinkhole 
CheckWhoISData dataresults 
if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "Nirsoft whois response", false
WhoIsIP_Lookup = strWhoIsIP_return
end if
End function


Sub LoadIPAuthorities
'load IP address assignments
LoadRIPE_Dat
LoadARIN_Dat
LoadTLD  
AddSLDtoDict 'populate second level domain dict
LoadSecondDNS 'Load second level DNS
LoadThirdDNS 'Load third level DNS
LoadAllTLD 'Load IANA list of TLDs
LoadWatchlist CurrentDirectory & "\APNIC.dat", DictAPNIC
LoadWatchlist CurrentDirectory &"\LACNIC.dat", DictLACNIC
LoadWatchlist CurrentDirectory &"\AFRINIC.dat", DictAFRINIC
end sub





Function SQL_Intelligence_Query(strSQLHashValue)
Dim strSQLquery
intLength = len(strSQLHashValue)
if intLength > 0 then
  strSQLquery = HashLenCheck(strSQLHashValue)
  Set Recordset = CreateObject("ADODB.Recordset")
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
  cmd.CommandText = adCmdStoredProc
  if strSQLquery <> "" and strSQLquery <> "unknown" then
    'strSQLquery = "select ResourceShortDesc,ResourceDescription,SourceName,Score from VendorCache LEFT OUTER JOIN ResourceInfo ON VendorCache.ResourceID = ResourceInfo.ResourceID  LEFT OUTER JOIN NamedSources ON ResourceInfo.NameID = NamedSources.NameID where VendorCache." & strSQLquery & " = '" & strSQLHashValue & "'"
    cmd.CommandText = "select ResourceShortDesc,ResourceDescription,SourceName,Score from VendorCache LEFT OUTER JOIN ResourceInfo ON VendorCache.ResourceID = ResourceInfo.ResourceID  LEFT OUTER JOIN NamedSources ON ResourceInfo.NameID = NamedSources.NameID where VendorCache." & strSQLquery & " = ?"
    'set objparameter = cmd.createparameter("@hashvalue", adChar, adParamInput, ,strSQLHashValue)
    set objparameter = cmd.createparameter("@hashvalue", 129, 1, intLength,strSQLHashValue)
    cmd.Parameters.Append objparameter
    'msgbox cmd.CommandText
      Recordset.Open cmd
    If not Recordset.EOF Then
      'Recordset.MoveFirst
      strShortDesc = Recordset.fields.item("ResourceShortDesc")  
      strDesc = Recordset.fields.item("ResourceDescription")
      strSourceName = Recordset.fields.item("SourceName")
      intScore = Recordset.fields.item("Score")  
      'Update adjusted malware score
      if isnumeric(intScore) then IntTmpAdjustedMalScore = IntTmpAdjustedMalScore + cint(intScore)
      'Add common name if one doesn't exist
      if strShortDesc <> "" and strDetectNameLineE = "|" then strDetectNameLineE = "|" & strShortDesc
      'Text output
      if strSourceName <> "" then
        strSQL_Intelligence_Output = strSQL_Intelligence_Output & strSQLHashValue & vbTab & strSourceName & " - " & strShortDesc & ": " & strDesc & vbcrlf
      end if
      'if strSourceName <> "" and strDesc <> "" and instr(strSQL_Intelligence_Output, strSourceName & " - " & strShortDesc & ": " & strDesc) = 0 Then  strSQL_Intelligence_Output = strSQL_Intelligence_Output & strSourceName & " - " & strShortDesc & ": " & strDesc & vbcrlf
        'msgbox strShortDesc & vbcrlf & strDesc & vbcrlf & strSourceName & vbcrlf & intScore
    end if
    Recordset.close
  end if
end if
end Function


Function HashLenCheck(StrHashValue)
Dim strReturnHashType
if len(StrHashValue) = 32 then 'md5
  strReturnHashType = "MD5"
elseif len(StrHashValue) = 40 then 'sha1
  strReturnHashType = "SHA1"
elseif len(StrHashValue) = 64 then 'sha256
  strReturnHashType = "SHA256"
else
  objShellComplete.popup "Error! Length of hash doesn't match supported hashes. Will use unknown folder. Len=" & len(StrHashValue) & vbCrLf & StrHashValue, 10

  strReturnHashType = "unknown"
end if
HashLenCheck = strReturnHashType
end function


Function MySQLcache(strVendName, strVendLastUp,strHashType, strHashval)
Set Recordset = CreateObject("ADODB.Recordset")
strTmpHashType = replace(strHashType, "\","")
'select strVendName, strVendLastUp from VendorCache where strHashType = strHashval
Set cmdMySQL = nothing
  Set cmdMySQL = createobject("ADODB.Command")
sSQL = "SELECT QueryVendCache(?,?,?,?)"
cmdMySQL.CommandText = sSQL
set objparameter0 = cmdMySQL.createparameter("strVendName", 129, 1, len(strVendName),strVendName)
cmdMySQL.Parameters.Append objparameter0
set objparameter0 = cmdMySQL.createparameter("strVendLastUp", 129, 1, len(strVendLastUp),strVendLastUp)
cmdMySQL.Parameters.Append objparameter0
set objparameter0 = cmdMySQL.createparameter("strHashType", 129, 1, len(strTmpHashType),strTmpHashType)
cmdMySQL.Parameters.Append objparameter0
set objparameter0 = cmdMySQL.createparameter("strHashval", 129, 1, len(strHashval),strHashval)
cmdMySQL.Parameters.Append objparameter0
  Recordset.Open cmdMySQL
Set cmdMySQL.ActiveConnection = Nothing
Set cmdMySQL = Nothing   
set Recordset.ActiveConnection = Nothing
 
MySQLcache = Recordset

end function


Function CacheLookup(strCacheLdata, strCLsubpath, StrCacheName, intCacheAge)
Dim fsoTMPData: Set fsoTMPData = CreateObject("Scripting.FileSystemObject")
dim StrlcCacheName: StrlcCacheName = lcase(StrCacheName) 'make sure all hashes are lower case
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim BoolGetNewCache: BoolGetNewCache = False
Dim strCLfpath
Dim strHashSubPath
Dim strTmpmTime

Dim objparameter0: set objparameter0 = nothing
Dim objparameter1: set objparameter1 = nothing
Dim objparameter2: set objparameter2 = nothing
Dim objparameter3: set objparameter3 = nothing
if instr(strCacheLdata, "'") then strCacheLdata = replace(strCacheLdata, "'", "%27")
if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "strCLsubpath=" & strCLsubpath,BoolEchoLog 
select case strCLsubpath
  case "\vt\"
    strTmpVendcName = "VirusTotal"
    strLastUpdate = "VTLastUpdate"
  case "\malshare\"
    strTmpVendcName = "MalShare"
    strLastUpdate = "MSLastUpdate"
  case "\xf\"
    strTmpVendcName = "XForce"
    strLastUpdate = "XFLastUpdate"
  case "\tc\"
    strTmpVendcName = "ThreatCrowd"
    strLastUpdate = "TCLastUpdate"
    case "\tg\"
      strTmpVendcName = "ThreatGRID"
      strLastUpdate = "TGLastUpdate"        
end select

strHashSubPath = HashLenCheck(StrlcCacheName)'Returns string MD5, SHA1, or SHA256

if isdate(strDateTimeLineE) then'use VirusTotal last scan date as the date first seen when saving to the database.
  strTmpmTime = DateDiff("s", "01/01/1970 00:00:00", strDateTimeLineE)
else
  strTmpmTime = DateDiff("s", "01/01/1970 00:00:00", now)
end if

Set Recordset = CreateObject("ADODB.Recordset")

if boolMySQLcache  = True then'Check MySQL for the cache data
  recordset = MySQLcache(strTmpVendcName, strLastUpdate, strCLsubpath, StrCacheName)
  If Recordset.EOF Then 
    BoolUpdateMySQL = True
  else
    strCacheLdata = Recordset.fields.item(strTmpVendcName)
    strDateCompare = Recordset.fields.item(strLastUpdate)
    if DateDiff("d", strDateCompare, now) > intCacheAge then
      'BoolGetNewCache = True no MySQL update function yet
    end if
  end if
  Recordset.close
  'Set date first seen

end if

If boolSQLcache = False or lcase(strCLsubpath) = "\cb\" or strCLsubpath = "\es\" or strCLsubpath = "\te\" or strCLsubpath = "\ms\" then
  strCLfpath = strCachePath & "\" & strCLsubpath & "\" & strHashSubPath & "\" & StrlcCacheName
  
  'strTmpCacheLineE = "|"
  If fsoTMPData.fileexists(strCLfpath) then 'load from cache
    Set objMTAFile = fsoTMPData.getfile(strCLfpath)
    if strDFSlineE = "" then strDFSlineE = objMTAFile.DateCreated 'set spreadsheet output for date first seen
    if DateDiff("d", objMTAFile.DateLastModified, now) > intCacheAge then BoolGetNewCache = True
    Set objMTAFile = nothing
  else
    BoolGetNewCache = True
  end if


  if BoolGetNewCache = True and strCacheLdata <> "" then

    if fsoTMPData.fileexists(strCLfpath) then _
    fsoTMPData.deletefile strCLfpath
    logdata strCLfpath, strCacheLdata ,False  
  elseif BoolGetNewCache = False and fsoTMPData.fileexists(strCLfpath) = True Then
    Set objMTAFile = fsoTMPData.OpenTextFile(strCLfpath)
     if not objMTAFile.AtEndOfStream then 'read file
        strCacheLdata = objMTAFile.readall
     end if 
     objMTAFile.close
     set objMTAFile = nothing
     strTmpCacheLineE = "|X"
  end if
else
  if strHashSubPath = "unknown" then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Unsupported hash value - " & StrCacheName,False 
	exit function
  end if
  if strTmpVendcName = "VirusTotal" and strDFSlineE = "" and strHashSubPath <> "" then 
    sSQL = "select DateFirstSeen from VendorCache where " & strHashSubPath & " = ? " 
    strDFSlineE = ReturnSQLiteItem(sSQL, StrlcCacheName, "DateFirstSeen") 'set spreadsheet output for date first seen
    if isnumeric(strDFSlineE) then
      if strDFSlineE > 0 then strDFSlineE = DateAdd("s", strDFSlineE, "01/01/1970 00:00:00")
    end if
  end if  
  strTmpQuery = ""
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
    
  
  if StrTmpMD5 = "" then
    StrTmpMD5 = getdata(strCacheLdata,chr(34),"md5" & chr(34) & ": " & chr(34))
    if StrTmpMD5 = "" then StrTmpMD5 =strFileMD5
    if StrTmpMD5 <> "" then strTmpQuery = strTmpQuery & " or MD5 = " & "?"
    set objparameter1 = cmd.createparameter("@MD5", 129, 1, 40,StrTmpMD5)
  end if
  if StrTmpSHA1 = "" then
    StrTmpSHA1 = getdata(strCacheLdata,chr(34),"sha1" & chr(34) & ": " & chr(34))
    if StrTmpSHA1 = "" then StrTmpSHA1 =strFileSHA1
    if StrTmpSHA1 <> "" then strTmpQuery = strTmpQuery & " or SHA1 = " & "?"
    set objparameter2 = cmd.createparameter("@SHA1", 129, 1, 40,StrTmpSHA1)
  end if
  if StrTMPSHA256 = "" then
    StrTMPSHA256 = getdata(strCacheLdata,chr(34),"sha256" & chr(34) & ": " & chr(34))
    if StrTMPSHA256 = "" then StrTMPSHA256 = strFileSHA256
    if StrTMPSHA256 <> "" then strTmpQuery = strTmpQuery & " or SHA256 = " & "?"
    set objparameter3 = cmd.createparameter("@SHA256", 129, 1, 64,StrTMPSHA256)
  end if  
  if instr(strTmpQuery, ucase(strHashSubPath) & " = '" & lcase(strCacheFilePath)) then
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "strTmpQuery=" & strTmpQuery,BoolEchoLog 
    strTmpQuery = right(strTmpQuery, len(strTmpQuery) -4)
    sSQL = "select MD5,SHA1,SHA256,IMPHash," & strTmpVendcName & "," & strLastUpdate & " from VendorCache where " & strTmpQuery
  else
   sSQL = "select MD5,SHA1,SHA256,IMPHash," & strTmpVendcName & "," & strLastUpdate & " from VendorCache where " & strHashSubPath & " = ? " & strTmpQuery
   set objparameter0 = cmd.createparameter("@VarHash", 129, 1, len(StrlcCacheName),StrlcCacheName)
  end if
     Set cmd = Nothing
      Set cmd = createobject("ADODB.Command")
    cmd.ActiveConnection = oCNCT
    cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
    if objparameter1 <> Empty then cmd.Parameters.Append objparameter1
    if objparameter2 <> Empty then cmd.Parameters.Append objparameter2
    if objparameter3 <> Empty then cmd.Parameters.Append objparameter3
    set objparameter0 = nothing
    set objparameter1 = nothing
    set objparameter2 = nothing
    set objparameter3 = nothing
  if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "sSQL=" & sSQL,BoolEchoLog 
      Recordset.Open cmd

  If not Recordset.EOF Then 
    
    'Recordset.MoveFirst

    intLastUpdate = Recordset.fields.item(strLastUpdate)
	
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "intLastUpdate=" & intLastUpdate,BoolEchoLog
    if isnumeric(intLastUpdate) then 'compare date
      epoch2date = DateAdd("s", intLastUpdate, "01/01/1970 00:00:00")
	  lastSeenDate = epoch2date
     if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt", "datediff=" & DateDiff("d", epoch2date, now),BoolEchoLog
	 boolRefresh = false
	 if DateDiff("d", strDFSlineE, now) > intRefreshAge then
		boolRefresh = false
	 elseif DateDiff("d",lastSeenDate , now) < intRefreshAge then
		boolRefresh = True
	 end if
     
	 if BoolDebugTrace = True then logdata strDebugPath & "\refresh" & "" & ".txt","boolRefresh=" & boolRefresh & "|" & "lastSeenDate=" & lastSeenDate & "|" & DateDiff("d",lastSeenDate , now) & "<>" &  intRefreshAge,BoolEchoLog
     if (DateDiff("d", epoch2date, now) < intCacheAge or DateDiff("d", epoch2date, now) > intCacheRefreshLimit) and strCacheLdata = "" and boolRefresh = false then 
      strTmpCacheLineE = "|X"
      strCacheLdata = Recordset.fields.item(strTmpVendcName)
      if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt","strCacheLdata=" & strCacheLdata,BoolEchoLog

     else
      BoolGetNewCache = True
     end if
	else
	 BoolGetNewCache = True
	end if
   if strCacheLdata <> "" and BoolGetNewCache = True then 'update cache  
    strCompareMD5 = Recordset.fields.item("MD5")
    if StrTmpMD5 <> "" and strCompareMD5 = "" then
      strQueryWrite = ", MD5 = ?"
      set objparameter0 = cmd.createparameter("@MD5", 129, 1, 32,StrTmpMD5)
    end if
    strCompareSHA1 = Recordset.fields.item("SHA1")
    if StrTmpSHA1 <> "" and strCompareSHA1 = "" then
      strQueryWrite = strQueryWrite & ", SHA1 = ?"
      set objparameter1 = cmd.createparameter("@SHA1", 129, 1, 40,StrTmpSHA1)
    end if
    strCompareSHA256 = Recordset.fields.item("SHA256")
    if StrTMPSHA256 <> "" and strCompareSHA256 = "" then
      strQueryWrite = strQueryWrite & ", SHA256 = ?"
      set objparameter2 = cmd.createparameter("@SHA256", 129, 1, 64,StrTMPSHA256)
    end if  
    strCompareIMP = Recordset.fields.item("IMPHash")
    if strFileIMP <> "" and strCompareIMP = "" then
      strQueryWrite = strQueryWrite & ", IMP = ?"
      set objparameter3 = cmd.createparameter("@IMPHash", 129, 1, 32,strFileIMP)
    end if
    set objparameter4 = cmd.createparameter("@HashVal", 129, 1, len(StrlcCacheName),StrlcCacheName)
    sSQL = "UPDATE VendorCache SET " & strTmpVendcName & " = ?, " & strLastUpdate & " = ? " & strQueryWrite & " where " & strHashSubPath & " = ?"
     Set cmd = Nothing
	Set cmd = createobject("ADODB.Command")
	cmd.ActiveConnection = oCNCT
    cmd.CommandText = sSQL
    set objparameter = cmd.createparameter("@Cache", 129, 1, len(strCacheLdata),strCacheLdata)
    cmd.Parameters.Append objparameter
    set objparameter = cmd.createparameter("@Date", 129, 1, len(strTmpmTime),cstr(strTmpmTime))

    cmd.Parameters.Append objparameter


    if isobject(objparameter0) then 
      if Not objparameter0 is Nothing then  cmd.Parameters.Append objparameter0
    end if
    if isobject(objparameter1) then 
      if Not objparameter1 is Nothing then cmd.Parameters.Append objparameter1
    end if
    if isobject(objparameter2) then
      if Not objparameter2 is Nothing then cmd.Parameters.Append objparameter2
    end if
    if isobject(objparameter3) then
      if Not objparameter3 is Nothing then cmd.Parameters.Append objparameter3
    end if
    if isobject(objparameter4) then
      if Not objparameter4 is Nothing then cmd.Parameters.Append objparameter4
    end if

    set objparameter0 = nothing
    set objparameter1 = nothing
    set objparameter2 = Nothing
    set objparameter3 = nothing        
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt","sSQL =" & sSQL,BoolEchoLog
    if BoolDebugTrace = True then logdata strCachePath & "\SQL" & "_hist" & ".txt",StrCacheName,False
    cmd.execute
   end if  

  elseif strCacheLdata <> "" then 'add new cache entry
    select case strHashSubPath 
      case "MD5"
        StrTmpMD5 = StrlcCacheName 
      Case "SHA1"
        StrTmpSHA1 = StrlcCacheName 
      Case "SHA256"
        strTmpqSHA256 = StrlcCacheName 
    end select
    if StrTmpMD5 <> "" then 
      strTmpqMD5 = ", MD5"
      strTmpfMD5 = ", ?"
      set objparameter0 = cmd.createparameter("@MD5", 129, 1, 32,StrTmpMD5)
    else
      strTmpqMD5 = ""
      strTmpfMD5 = ""
    end if
     if StrTmpSHA1 <> "" then 
      strTmpqSHA1 = ", SHA1"
      strTmpfSHA1 = ", ?"
      set objparameter1 = cmd.createparameter("@SHA1", 129, 1, 40,StrTmpSHA1)
    else
      strTmpqSHA1 = ""
      strTmpfSHA1 = ""
    end if
     if StrTMPSHA256 <> "" then 
      strTmpqSHA256 = ", SHA256"
      strTmpfSHA256 = ", ?"
      set objparameter2 = cmd.createparameter("@SHA256", 129, 1, 64,StrTMPSHA256)
    else
      strTmpqSHA256 = ""
      strTmpfSHA256 = ""
    end if

    if strFileIMP <> "" then 
      strTmpIMP = ", IMPHash"
      strTmpfIMP = ", ?"
      set objparameter3 = cmd.createparameter("@IMPHash", 129, 1, 32,strFileIMP)
    else
      strTmpIMP = ""
      strTmpfIMP = ""
    end if
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL_hist.txt",StrCacheName,False
    strTmpHashText = strTmpqMD5 & strTmpqSHA1 & StrTMPqSHA256 
    strTmpHashValues = strTmpfMD5 & strTmpfSHA1 & strTmpfSHA256 
    if left(strTmpHashText, 2) = ", " then strTmpHashText = right(strTmpHashText, Len(strTmpHashText) -2)
    if left(strTmpHashValues, 1) = "," then strTmpHashValues = right(strTmpHashValues, Len(strTmpHashValues) -1)
    sSQL = "INSERT INTO VendorCache(" & strTmpHashText & ", " & _
    strTmpVendcName & ", " & strLastUpdate & ", DateFirstSeen" & strTmpIMP & ") VALUES(" & strTmpHashValues & ", ?, ?, ?" & strTmpfIMP & ")"
     Set cmd = Nothing
  Set cmd = createobject("ADODB.Command")
cmd.ActiveConnection = oCNCT
    if instr(sSQL, "VALUES(, ")  then sSQL = replace(sSQL, "VALUES(, ", "VALUES(")
    if instr(sSQL, "VendorCache(, ")  then sSQL = replace(sSQL, "VendorCache(, ", "VendorCache(")
    cmd.commandtext = sSQL
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt","sSQL =" & sSQL,BoolEchoLog
    if isobject(objparameter0) then 
      if Not objparameter0 is Nothing then  cmd.Parameters.Append objparameter0
    end if
    if isobject(objparameter1) then 
      if Not objparameter1 is Nothing then cmd.Parameters.Append objparameter1
    end if
    
    if isobject(objparameter2) then
      if Not objparameter2 is Nothing then cmd.Parameters.Append objparameter2
    end if

    set objparameter = cmd.createparameter("@Cache", 129, 1, len(strCacheLdata),strCacheLdata)
    cmd.Parameters.Append objparameter
    set objparameter = cmd.createparameter("@Date", 129, 1, len(strTmpmTime),cstr(strTmpmTime))
    cmd.Parameters.Append objparameter    
    set objparameter = cmd.createparameter("@Date", 129, 1, len(strTmpmTime),cstr(strTmpmTime))
    cmd.Parameters.Append objparameter  
    if isobject(objparameter3) then
      if Not objparameter3 is Nothing then cmd.Parameters.Append objparameter3
    end if
    set objparameter0 = nothing
    set objparameter1 = nothing
    set objparameter2 = nothing
    set objparameter3 = nothing  
    'msgbox cmd.commandtext
    'msgbox cmd.parameters(0) & vbcrlf & _
    'cmd.parameters(1) & vbcrlf & _
    'cmd.parameters(2) & vbcrlf & _
    'cmd.parameters(4) & vbcrlf & _
    'cmd.parameters(5) & vbcrlf 
    cmd.execute
  else
   
    if BoolDebugTrace = True then logdata strDebugPath & "\SQL" & "" & ".txt","no records returned.",BoolEchoLog
  end if

  Recordset.close
end if
CacheLookup = strCacheLdata
'msgbox StrlcCacheName & "|" & "BoolGetNewCache=" & BoolGetNewCache & "|" & strCacheLdata 'debugline
end function


Function IsPrivateIP(strIP)
Dim boolReturnIsPrivIp
Dim ArrayOctet
boolReturnIsPrivIp = False
if isIPaddress(strIP) = False then
  IsPrivateIP = False
  exit function
end if
if left(strIP,3) = "10." then
  boolReturnIsPrivIp = True
elseif left(strIP,4) = "172." then
  ArrayOctet = split(strIP,".")
  if ArrayOctet(1) >15 and ArrayOctet(1) < 32 then
    boolReturnIsPrivIp = True
  end if
ElseIf left(strIP,7) = "192.168" then
  boolReturnIsPrivIp = True
elseif left(strIP,7) = "169.254" then 'APIPA
  boolReturnIsPrivIp = True
ElseIf left(strIP,6) = "fe80::" Then 'IPv6 link-local
  boolReturnIsPrivIp = True
elseif Replace(  Replace(strIP,":","")   , "0","") = "1" Then 'IPv6 loop back
  boolReturnIsPrivIp = True
End if
IsPrivateIP = boolReturnIsPrivIp
End Function


Function NSRL_Lookup(strNSLRhash)
if BoolNSRLLookup = True then
  'This function requires a Whois client and has only been test with http://rjhansen.github.io/nsrllookup/
  Dim strWhoIsIP_return
  Set sh_WhoIsIP = WScript.CreateObject("WScript.Shell")
  Set fso_WhoIsIP = CreateObject("Scripting.FileSystemObject")

  ExecQuery = "cmd.exe /c echo " & strNSLRhash & " | nsrllookup -k "  & ">" & chr(34) & strDebugPath & "NSRL.txt" & chr(34)   

    ErrRtn = sh_WhoIsIP.run ("%comspec% /c " &  ExecQuery,0 ,True)
    if ErrRtn <> 0 then BoolNSRLLookup = False
   set readfilePath = fso_WhoIsIP.OpenTextFile(strDebugPath & "\NSRL.txt", 1, false)
  if not readfilePath.AtEndOfStream then dataresults = readfilepath.readall
  readfilePath.close
  set readfilePath =  Nothing
  if dataresults = "" then
    NSRL_Lookup = False
  else
    if Instr(dataresults, "connection refused") then
      NSRL_Lookup = False
    else
      NSRL_Lookup = True
    end if
  end if
end if  
End function


Function Dload_DDNS(strURLDownload,strDownloadName)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")

Dim strReturnInfo

  objHTTP.open "GET", strURLDownload, False

on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " " & strURLDownload & " File download failed with HTTP error. - " & err.description,False 
    exit function 
  end if
on error goto 0  
strReturnInfo = False
if instr(objHTTP.responseText,"this is a listdynamic dns providers") then
  LogData CurrentDirectory & strDownloadName,objHTTP.responseText, false
  strReturnInfo = True
end if

Dload_DDNS = strReturnInfo
Set objHTTP = Nothing
end Function

Function ThreatCrowdHashLookup(strTC_ScanItem)
If tcHashLookedUp = True Then Exit Function
ThreatCrowdHashLookup = CheckThreatCrowd("md5", strTC_ScanItem)
if BoolDebugTrace = True then logdata strHashReportsPath & "\TCrowd_hash_" & strData & ".txt", strTC_ScanItem & vbtab & strTmpTCrowd,BoolEchoLog 
if strTmpTCrowd <> "" then
	if strTCrowd_Output = "" then
		strTCrowd_Output = "https://www.threatcrowd.org/malware.php?md5=" & strTC_ScanItem
	else
		strTCrowd_Output = strTCrowd_Output & vbcrlf & "https://www.threatcrowd.org/malware.php?md5=" & strTC_ScanItem
	end if
	strTMPTCrowdLine = "|X"
end If
tcHashLookedUp = True
End Function         

Function CheckThreatCrowd(StrTC_dataType, strTC_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
dim strAssocWith
Dim strTCrowdreturn
strAVEurl = "http://www.threatcrowd.org/searchApi/v1/api.php?type=" & StrTC_dataType & "&query="

if ishash(strTC_ScanItem) and BoolDisableCacheLookup = false then
  if booluseSQLite = False then
    strTCrowdreturn = CacheLookup("", "\tc\", strTC_ScanItem, intHashCacheThreashold)
  else
      sSQL = "select ThreatCrowd from VendorCache where MD5 = ? " 
    strTCrowdreturn = ReturnSQLiteItem(sSQL, strTC_ScanItem, "MD5")
  end if
elseif booluseSQLite = True and ishash(strTC_ScanItem) =false and isipaddress(strTC_ScanItem) = False and BoolDisableCacheLookup = false then
  sSQL = "select TCdomain from DomainVend where DomainName = ? " 
  strTCrowdreturn = ReturnSQLiteItem(sSQL, strTC_ScanItem, "TCdomain")
end if

if strTCrowdreturn = "" then
  objHTTP.open "GET", strAVEurl & strTC_ScanItem, False

  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Threat Crowd lookup failed with HTTP error. - " & err.description,False 
      exit function 
    end if
  on error goto 0  

  if BoolDebugTrace = True then logdata strDebugPath & "\VT_TC" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  strTCrowdreturn = objHTTP.responseText
  'cache everything so we don't get blacklisted
  if instr(strTCrowdreturn,"Web server is returning an unknown error") then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Threat Croud lookup failed with HTTP error. - Web server is returning an unknown error",False 
  else
    if StrTC_dataType = "md5" then 
      if len(strTCrowdreturn) = 0 then _
        strTCrowdreturn = "NULL"
      if BoolDisableCaching = False and booluseSQLite = False then CacheLookup strTCrowdreturn, "\tc\", strTC_ScanItem, intHashCacheThreashold
    end if
  end if
end if

if len(strTCrowdreturn) > 0 then
  if instr(strTCrowdreturn, "the web page can not be displayed") then 
    boolUseThreatCrowd = False 
    exit function
  end if
  if StrTC_dataType = "domain" then strAssocWith = "domain name"
  if StrTC_dataType = "ip" then strAssocWith = "IP address"
  if StrTC_dataType = "md5" then 
    if instr(strTCrowdreturn, ",") then 
      strAssocWith = "hash"
      CheckThreatCrowd = "ThreatCrowd has information on the hash " & strAssocWith & " - " & strAVEurl & strTC_ScanItem
    end if
  elseif instr(strTCrowdreturn, "MD5,") then 
    CheckThreatCrowd = "ThreatCrowd has samples associated with " & strAssocWith & " - " & strAVEurl & strTC_ScanItem
  end if
end if
'MsgBox strTCrowdreturn
 
Set objHTTP = Nothing
end Function


Function ParseVTforIPaddress(strVTresponseText)
Dim arrayIP_address
Dim StrTmpIP_address
Dim StrTmpIP_resolve
DIm DictIP_resolve
Dim strReturn_IP
Set DictIP_resolve = CreateObject("Scripting.Dictionary")

'msgbox instr(strVTresponseText, "{" & chr(34) & "last_resolved" & chr(34) & ": ")
arrayIP_address = split(strVTresponseText, "{" & chr(34) & "last_resolved" & chr(34) & ": ")
for intIPR_loc = 1 to ubound(arrayIP_address)
  if left(arrayIP_address(intIPR_loc),4) <> "null" then StrTmpIP_resolve= GetData(arrayIP_address(intIPR_loc),chr(34),chr(34))
 StrTmpIP_address = GetData(arrayIP_address(intIPR_loc),chr(34),", " & Chr(34) & "ip_address" & Chr(34) & ": " & chr(34))
  'msgbox StrTmpIP_address & ", " & StrTmpIP_resolve
  if DictIP_resolve.exists(StrTmpIP_address) then
    if datediff("s", DictIP_resolve.item(StrTmpIP_address), StrTmpIP_resolve) > 0 then
      DictIP_resolve.item(StrTmpIP_address) = StrTmpIP_resolve
    
    end if
  else
    DictIP_resolve.add StrTmpIP_address, StrTmpIP_resolve
  end if
  'IP address watch list
  strIpDwatchLineE = MatchIpDwatchLIst(StrTmpIP_address) 'watch list check
next
StrTmpIP_resolve = ""
For each StrTmpIP_address in DictIP_resolve
  if StrTmpIP_resolve = "" then
    StrTmpIP_resolve = DictIP_resolve.item(StrTmpIP_address) 
    strReturn_IP = StrTmpIP_address
  else
    if datediff("s", StrTmpIP_resolve, DictIP_resolve.item(StrTmpIP_address)) > 0 then
      StrTmpIP_resolve = DictIP_resolve.item(StrTmpIP_address) 
      strReturn_IP = StrTmpIP_address
    end if
  end if
next
ParseVTforIPaddress = strReturn_IP
end function


Sub UpdateVTPositives(intCategory, IntPositives)
  '0 "detected_downloaded_samples" 
  '1 detected_referrer_samples" & chr(34) & ": [")
  '2 detected_communicating_samples" & chr(34) & ": [")
  '3 detected_urls" & chr(34) & ": [")
  'msgbox "UpdateVTPositives(" & intCategory & ", " & IntPositives & ")"
  Dim ReturnPipePositive
if instr(strTmpVTPositvLineE, "|") then
	ArrayVTPositives = split (strTmpVTPositvLineE, "|")
	'msgbox ArrayVTPositives(intCategory + 1) & " < " & IntPositives
	if cint(ArrayVTPositives(intCategory + 1)) < cint(IntPositives) then
		for intCategoryCount = 0 to 3
			'msgbox intCategory & " = " & intCategoryCount
			'msgbox intCategory = intCategoryCount
			if intCategory = intCategoryCount then
				ReturnPipePositive = AppendValuesList(ReturnPipePositive,IntPositives,"|")
			else
				ReturnPipePositive = AppendValuesList(ReturnPipePositive, ArrayVTPositives(intCategoryCount +1),"|")
			end if
		next
	end if
else 'need to use this for the VirusTotal v3 API

end if
'msgbox "ReturnPipePositive=" & ReturnPipePositive
if ReturnPipePositive <> "" then
	strTmpVTPositvLineE = "|" & ReturnPipePositive
end if
'msgbox "strTmpVTPositvLineE=" & strTmpVTPositvLineE
end Sub


Function ParseVTforPositives(strVTresponseText)
Dim IntReturnPositives
Dim IntAggreRP
Dim strDetectURLs
'get detected URLs only
for intPTVFT = 0 to 3
  if intPTVFT = 0 then strDetectURLs = getdata(strVTresponseText, "]", chr(34) & "detected_downloaded_samples" & chr(34) & ": [")
  if intPTVFT = 1 then strDetectURLs = getdata(strVTresponseText, "]", chr(34) & "detected_referrer_samples" & chr(34) & ": [")
  if intPTVFT = 2 then strDetectURLs = getdata(strVTresponseText, "]", chr(34) & "detected_communicating_samples" & chr(34) & ": [")
  if intPTVFT = 3 then strDetectURLs = getdata(strVTresponseText, "]", chr(34) & "detected_urls" & chr(34) & ": [")
  IntReturnPositives = 0
  if strDetectURLs <> "" then
    if instr(strDetectURLs,chr(34) & "positives" & chr(34) & ":") then
      arrayPositives = split(strDetectURLs,chr(34) & "positives" & chr(34) & ":")
      
      for intPositv_loc = 1 to ubound(arrayPositives)
        StrTmpPositives = GetData(arrayPositives(intPositv_loc),","," ")
        if isnumeric(StrTmpPositives) then
          'msgbox StrTmpPositives & ">" & IntReturnPositives
           if BoolDebugTrace = True then LogData strDebugPath & "\VT_SS_positiv.log", intPTVFT & "__" & StrTmpPositives & ">" & IntReturnPositives, false
          if int(StrTmpPositives) > int(IntReturnPositives) then IntReturnPositives = StrTmpPositives

        end if
      next
    end if
  end if
  IntAggreRP = IntAggreRP & "|" & IntReturnPositives
next
ParseVTforPositives = IntAggreRP
end function


Function CheckBadValues(strBVcheck)
if strBVcheck = "" or strBVcheck = "N/A" or strBVcheck = " " or strBVcheck = " -"  or strBVcheck = " --" or strBVcheck = "-" or strBVcheck = "--" or strBVcheck = "|" or strBVcheck = "Unknown" or strBVcheck = "|Unknown" then
  CheckBadValues = True
else
  CheckBadValues = False
end if
end function


Function ParseVTIPOwner(strVTresponseText)
Dim StrPVTOwner_Return
 if instr(strVTresponseText, chr(34) & "as_owner" & chr(34) & ": ") then

    StrPVTOwner_Return = getdata(strVTresponseText, chr(34), chr(34) & "as_owner" & chr(34) & ":" & chr(34))
    if StrPVTOwner_Return = "" then StrPVTOwner_Return = getdata(strVTresponseText, chr(34), chr(34) & "as_owner" & chr(34) & ": " & chr(34))
    if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "StrPVTOwner_Return =" & StrPVTOwner_Return, false
 end if
ParseVTIPOwner = StrPVTOwner_Return
end function 


Function CheckWhoISData(strTmpWhoisResponse)'check for sinkhole domain
Dim strTmpRegistrantName
Dim strTmpRegistrantOrg
Dim strTmpNameServer
if instr(strTmpWhoisResponse, "Status: clientTransferProhibited") then
  if instr(strTmpWhoisResponse, "Status: clientUpdateProhibited") then
    if instr(strTmpWhoisResponse, "Status: clientRenewProhibited") then
      if instr(strTmpWhoisResponse, "Status: clientDeleteProhibited") then
        strTmpDomainRestric = "|X"
      end if
    end if
  end if
end if

if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "-------------------" & vbcrlf & "strTmpWhoisResponse:" & strTmpWhoisResponse, false
if instr(strTmpWhoisResponse, "Registrant Name: ") then
	strTmpRegistrantName = getdata(strTmpWhoisResponse, ":", "Registrant Name: ")
	strTmpRegistrantOrg = getdata(strTmpWhoisResponse, ":", "Registrant Organization: ") 
	if strTmpRegistrantName <> "" and strTmpRegistrantOrg <> "" then
		SinkholeRegistrantCheck strTmpRegistrantName, strTmpRegistrantOrg
	end if
end if
if instr(strTmpWhoisResponse, "\nRegistrant Organization:") then
  strTmpRegistrantOrg = getdata(strTmpWhoisResponse, "\", "\nRegistrant Organization:")
	if instr(strTmpRegistrantOrg, vbcr) > 0 then 
		strTmpRegistrantOrg = left(strTmpRegistrantOrg,instr(strTmpRegistrantOrg, vbcr) -1)
		
	end if
end if
if CheckBadValues(StrPVTWhoIS_Return) and instr(strTmpWhoisResponse, "\nRegistrant Name:") then
	strTmpRegistrantName = getdata(strTmpWhoisResponse, "\", "\nRegistrant Name:")
end if
if instr(strTmpRegistrantName, vbcr) > 0 then 
	strTmpRegistrantName = left(strTmpRegistrantName,instr(strTmpRegistrantName, vbcr) -1)
end if
 
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "strTmpRegistrantName=" & strTmpRegistrantName, false
if strTmpRegistrantName = "" then
	strTmpRegistrantName = rgetdata(strTmpWhoisResponse, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Name" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "name" & chr(34) & "}")
end if
if strTmpRegistrantName = "Microsoft Corporation Digital Crimes Unit" then
	strTmpSinkHole = "|X"
end if
if strTmpRegistrantName <> "" and strTmpRegistrantOrg <> "" then
	SinkholeRegistrantCheck strTmpRegistrantName, strTmpRegistrantOrg
end if
  
if strTmpSinkHole = "|" or strTmpSinkHole = "" then
	if instr(strTmpWhoisResponse, "Name Server: ") then
		strTmpNameServer = getdata(strTmpWhoisResponse, ":", "Name Server: ")
		if instr(strTmpNameServer, "\n") then 'Fix VirusTotal name server parsing (was including \n)
			strTmpNameServer = left(strTmpNameServer, instr(strTmpNameServer, "\n") -1)
		end if
		strTmpNameServer = ucase(strTmpNameServer)
		SinkholeNSCheck strTmpNameServer

	end if
	if instr(strTmpWhoisResponse, "nameservers" & chr(34) & ":[") > 0 then
		'whoapi name servers
		strTmpNameServer = getdata(strTmpWhoisResponse, "]", "nameservers" & chr(34) & ":[")
		arrayNameServers = split(strTmpNameServer, chr(34) & "," & Chr(34))
		for each nsEntry in arrayNameServers
			if strTmpSinkHole = "|" or strTmpSinkHole = "" then
				SinkholeNSCheck replace(ucase(nsEntry), chr(34), "")
			End If
		next
	end if
	'msgbox "Alien in string:" & instr(strTmpWhoisResponse, chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Name Servers" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "name_servers " & chr(34) & "}")
	if instr(strTmpWhoisResponse, chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Name Servers" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "name_servers " & chr(34) & "}") > 0 then
		'AlienVault name servers
		strTmpNameServer = rgetdata(strTmpWhoisResponse, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Name Servers" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "name_servers " & chr(34) & "}")
		'msgbox "strTmpNameServer=" & strTmpNameServer	
		if strTmpNameServer <> "" then
			SinkholeNSCheck ucase(strTmpNameServer)
		end if
	end if
  end if
end function


Sub SinkholeRegistrantCheck(strRegistrantName, strRegistrantOrg)
'if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "SinkholeRegistrantCheck:" & strRegistrantName & "|" & strRegistrantOrg, false
  if instr(strRegistrantName, "Digital Crimes Unit") and instr(strRegistrantOrg, "Microsoft Corporation") then
    strTmpSinkHole = "|X"
  end if
end sub


Sub SinkholeNSCheck(strNameServer)
strNameServerNew = strNameServer
if instr(strNameServerNew, vbcr) > 0 then strNameServerNew = left(strNameServerNew, instr(strNameServerNew, vbcr) -1)

if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "name Server sink check:" & strNameServerNew, false
if instr(strNameServerNew, ".MICROSOFTINTERNETSAFETY.NET") then
  strTmpSinkHole = "|.MICROSOFTINTERNETSAFETY.NET"
elseif instr(strNameServerNew, "NS1.SINKHOLE.SHADOWSERVER.ORG") then
'SINKHOLE-00.SHADOWSERVER.ORG https://www.virustotal.com/en/domain/init.icloud-analysis.com/information/
  strTmpSinkHole = "|NS1.SINKHOLE.SHADOWSERVER.ORG"
elseif instr(strNameServerNew, "SINKHOLE") or instr(strNameServerNew,"SNKHOLE") then

  if instr(strNameServerNew, "\N") then 
	strTmpSinkHole = "|" & left(strNameServerNew,instr(strNameServerNew, "\N")-1)
  elseif instr(strNameServerNew, vblf) then 
	strTmpSinkHole = "|" & left(strNameServerNew,instr(strNameServerNew, vblf)-1)
  else
	'strTmpSinkHole = "|" & "X"
	strTmpSinkHole = "|" & strNameServerNew
  end if
  
  
elseif instr(strNameServerNew, ".CSOF.NET") then 'https://www.virusbulletin.com/uploads/pdf/magazine/2016/VB2016-Karve-etal.pdf
	strTmpSinkHole = "|.CSOF.NET"
elseif instr(strNameServerNew, ".REG.RU") then 'Not all domains are sinkhole 'https://www.virusbulletin.com/uploads/pdf/magazine/2016/VB2016-Karve-etal.pdf
	'strTmpSinkHole = "|.REG.RU"
elseif instr(strNameServerNew, ".HONEYBOT.US") then 'https://www.virusbulletin.com/uploads/pdf/magazine/2016/VB2016-Karve-etal.pdf
	strTmpSinkHole = "|.HONEYBOT.US"
elseif instr(strNameServerNew, ".ALICES-REGISTRY.COM") then'https://www.virusbulletin.com/uploads/pdf/magazine/2016/VB2016-Karve-etal.pdf
	strTmpSinkHole = "|.ALICES-REGISTRY.COM"		
elseif instr(strNameServerNew, ".SINKDNS.ORG") then
	strTmpSinkHole = "|.SINKDNS.ORG"		
end if
end sub


Function ParseVTlist(strPVTL_path)'precheck/preprocess vtlist.txt for conflicting scan items (spreadsheet mode only)
Dim strVTlist
Dim arrayVTlist
Dim BoolHashExists
Dim BoolNonHashExists
Dim intAnswer
boolNoIPdomain = False
strVTlist = ReadTextFile(strPVTL_path)
intAnswer = vbNo
if instr(strVTlist,vbtab) > 0  then
  strVTlist = replace(strVTlist, vbtab, "")
  if intAnswer = vbno then intAnswer = msgbox ("vtlist.txt contains tab characters. Would you like to remove tab characters for the script to continue? Script will exit if you choose no.",vbYesNo, "VTTL Question")
  if intAnswer = vbYes Then 
    LogoverwriteData strPVTL_path, strVTlist, false 
    ParseVTlist = ParseVTlist(strPVTL_path)
    exit function
  else
    wscript.quit(462)
  end if 
end if

if instr(strVTlist,vbcrlf) then

  arrayVTlist = split(strVTlist,vbcrlf)
  For each strVTitem in arrayVTlist


    if ishash(strVTitem) = True then
       if BoolNonHashExists = True then
        msgbox "error around line " & strVTitem
        ParseVTlist = 3
        exit function
       end if
       BoolHashExists = True
    elseif strVTitem <> "" then
       if BoolHashExists = True then
        msgbox "Type match error in vtlist.txt with line " & chr(34) & strVTitem  & chr(34)
        ParseVTlist = 3
        exit function
       end if
      BoolNonHashExists = True
    end if
  next
else
  if instr(strVTlist,vblf) > 0 and instr(strVTlist,vbcr) = 0 then
    strVTlist = replace(strVTlist, vblf, vbCrLf)
    intAnswer = msgbox ("vtlist.txt is missing carriage return. Would you like to add carriage returns for the script to continue? Script will exit if you choose no.",vbYesNo, "VTTL Question")
      if intAnswer = vbYes Then 
        LogoverwriteData strPVTL_path, strVTlist, false 
        ParseVTlist = ParseVTTLlist(strPVTL_path)
        exit function
      else
        wscript.quit(463)
      end if

  else
    if ishash(strVTlist) = True then
      BoolHashExists = True
    elseif instr(strVTlist, ".") = 0 and instr(strVTlist, ":") = 0 then
      boolNoIPdomain = True
      if BoolNonHashExists = True then
        msgbox "Type match error in vtlist.txt with line " & chr(34) & strVTitem  & chr(34)
        ParseVTlist = 4
      end if
      exit function
    elseif strVTlist <> "" then
      BoolNonHashExists = True
    end if
  end if
end if
if BoolHashExists = False and BoolNonHashExists = True and boolNoIPdomain = True then
  ParseVTlist = 4
elseif BoolHashExists = True and BoolNonHashExists = True then
  ParseVTlist = 3
elseif BoolHashExists = True and BoolNonHashExists = False then
  ParseVTlist = 2
elseif BoolHashExists = False and BoolNonHashExists = True then
  ParseVTlist = 1
else
  ParseVTlist = 0
end if
end function


Function ReadTextFile(StrRTFpath) 
  if objFSO.fileexists(StrRTFpath)  = True then
    Set objFile = objFSO.OpenTextFile(StrRTFpath)
    if Not objFile.AtEndOfStream then  strRTFText = objFile.ReadAll
    objFile.close
    ReadTextFile = strRTFText
  else
    'logdata strDebugPath & "\Read-file.log", StrRTFpath " does not exist!", false
  end if
end function


Sub LoadEncyclopedia_Cache
Dim strTmpdatFilePath

LoadDSWhitelist
'create missing dat files - no longer doing this. Need to download from github
'if objFSO.fileexists(strCachePath & "\PUP.dat") = False then WritePUP_Dat
'if objFSO.fileexists(strCachePath & "\HKTL.dat") = False then WriteHKTL_Dat

'load dat files
for intCountdatfiles = 0 to 24
  select case intCountdatfiles
    case 0
      strTmpdatFilePath = strCachePath & "\Microsoft.dat"
    case 1
      strTmpdatFilePath = strCachePath & "\TrendMicro.dat"
    case 2
      strTmpdatFilePath = strCachePath & "\McAfee.dat"
    case 3
      strTmpdatFilePath = strCachePath & "\Sophos.dat"
    case 4
      strTmpdatFilePath = strCachePath & "\Symantec.dat"
    case 5
      strTmpdatFilePath = strCachePath & "\ESET.dat"
    case 6
      strTmpdatFilePath = strCachePath & "\Avira.dat"
    case 7
      strTmpdatFilePath = strCachePath & "\DrWeb.dat"
    case 8 
      strTmpdatFilePath = strCachePath & "\EncyclopediaN.dat"
    case 9
      'strTmpdatFilePath = strCachePath & "\ThreatExpert.dat" 'no longer exists
    case 10
      strTmpdatFilePath = strCachePath & "\PUP.dat"      
    case 11
      strTmpdatFilePath = strCachePath & "\hktl.dat"
    case 12
      strTmpdatFilePath = strCachePath & "\ds_mal.dat"
    case 13
      strTmpdatFilePath = strCachePath & "\ds_pup.dat"
    case 14
      strTmpdatFilePath = strCachePath & "\ds_gry.dat"
    case 15
      strTmpdatFilePath = strCachePath & "\digsig.dat"
    case 16
      strTmpdatFilePath = strCachePath & "\pathvend.dat"
    case 17
      strTmpdatFilePath = strCachePath & "\orgwho.dat"
    case 18
      strTmpdatFilePath = strCachePath & "\whois.dat"
    case 19
      strTmpdatFilePath = strCachePath & "\F-Secure.dat"
    case 20
      strTmpdatFilePath = strCachePath & "\Panda.dat"	 
    case 21
      strTmpdatFilePath = strCachePath & "\Bitdefender.dat"	 	
	case 22
	  strTmpdatFilePath = strCachePath & "\NIDS_Sig.dat"
	case 23
		strTmpdatFilePath = strCachePath & "\NIDS_Cat.dat"
	case 24
		strTmpdatFilePath = strCachePath & "\family.dat"
	end select
  if objFSO.fileexists(strTmpdatFilePath) then
    Set objFile = objFSO.OpenTextFile(strTmpdatFilePath)
    Do While Not objFile.AtEndOfStream
      if not objFile.AtEndOfStream then 'read file
          On Error Resume Next
          strData = objFile.ReadLine 
          on error goto 0
          if instr(strData,"|") then
            arrayTmpDatf = split(strData,"|")
            select case intCountdatfiles
              case 0
                if DictMicrosoftEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictMicrosoftEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 1
                if DictTrendMicroEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictTrendMicroEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 2
                if DictMcAfeeEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictMcAfeeEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 3
                if DictSophosEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictSophosEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 4
                if DictSymantecEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictSymantecEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 5
                if DictESETEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictESETEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 6
                if DictAviraEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictAviraEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 7
                if DictDrWebEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictDrWebEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
              case 8
                if dictEncyclopediaNegative.exists(arrayTmpDatf(0) & "|" & arrayTmpDatf(1)) = False then _
                 dictEncyclopediaNegative.add arrayTmpDatf(0) & "|" & arrayTmpDatf(1), ""
              case 9
                'if DictThreatExpertEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                ' DictThreatExpertEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1) 
              case 10
                if DictPUANames.exists(arrayTmpDatf(0)) = False then _
                 DictPUANames.add arrayTmpDatf(0), arrayTmpDatf(1)  
              case 11
                if DictHktlNames.exists(arrayTmpDatf(0)) = False then _
                 DictHktlNames.add arrayTmpDatf(0), arrayTmpDatf(1)                   
               case 12
                if DictMalDSigNames.exists(arrayTmpDatf(0)) = False then _
                 DictMalDSigNames.add arrayTmpDatf(0), arrayTmpDatf(1)                   
               case 13
                if DictPUADSigNames.exists(arrayTmpDatf(0)) = False then _
                 DictPUADSigNames.add arrayTmpDatf(0), arrayTmpDatf(1)                   
               case 14
                if DictGrayDSigNames.exists(arrayTmpDatf(0)) = False then _
                 DictGrayDSigNames.add arrayTmpDatf(0), arrayTmpDatf(1)                   
               case 15
                if DictDSigNames.exists(arrayTmpDatf(0)) = False then _
                 DictDSigNames.add arrayTmpDatf(0), arrayTmpDatf(1)                   
               case 16
                on error resume next
                if DictPathVendorStat.exists(arrayTmpDatf(0) & "|" & arrayTmpDatf(1)) = False then _
                DictPathVendorStat.add arrayTmpDatf(0) & "|" & arrayTmpDatf(1), arrayTmpDatf(2)
                if err.number <> 0 then msgbox arrayTmpDatf(0) & "|" & arrayTmpDatf(1) & "|" & arrayTmpDatf(2)
                on error goto 0
               case 17
                if DictOrgWhois.exists(arrayTmpDatf(0)) = False then _
                 DictOrgWhois.add arrayTmpDatf(0), arrayTmpDatf(1)  
               case 18
                if DictWhois.exists(arrayTmpDatf(0)) = False then _
                 DictWhois.add arrayTmpDatf(0), arrayTmpDatf(1)  
			   Case 19
				 if DictFSecureEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictFSecureEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
			   Case 20
				if DictPandaEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictPandaEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
			   Case 21
				if DictBitdefenderEncyclopedia.exists(arrayTmpDatf(0)) = False then _
                 DictBitdefenderEncyclopedia.add arrayTmpDatf(0), arrayTmpDatf(1)
				Case 22
					if dictNIDSsigName.exists(arrayTmpDatf(0)) = False then _
					dictNIDSsigName.add arrayTmpDatf(0), arrayTmpDatf(1)
				 case 23
					if dictNIDScategory.exists(arrayTmpDatf(0)) = False then _
					dictNIDScategory.add arrayTmpDatf(0), arrayTmpDatf(1)			
				Case 24
					if dictFamilyNames.exists(arrayTmpDatf(0)) = False then _
					dictFamilyNames.add arrayTmpDatf(0), arrayTmpDatf(1)		
			end select
        
          end if
      end if
    loop    
  end if
next
end sub


Function Encyclopdia_Cache(strAV_Vendor, strVendorDetectionName)
Dim strTmpEC_URLreturn
Dim BoolSkipElookup
BoolSkipElookup = False
if instr(lcase(strVendorDetectionName), "adware") then BoolSkipElookup = True
if instr(lcase(strVendorDetectionName), "unwanted") then BoolSkipElookup = True
if instr(lcase(strVendorDetectionName), "toolbar") then BoolSkipElookup = True

if BoolCreateSpreadsheet = True then
  if instr(strVendorDetectionName, "CRCK_KEYGEN") then BoolSkipElookup = True
  if instr(strVendorDetectionName, "HackTool:Win32/Keygen") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), "riskware") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), "pua_") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), "pua.") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), " pup") then BoolSkipElookup = True 'McAfee|Generic PUP
  if instr(lcase(strVendorDetectionName), "searchsuite") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), "adw_") then BoolSkipElookup = True
  if instr(lcase(strVendorDetectionName), "casfortune") then BoolSkipElookup = True  
  if instr(lcase(strVendorDetectionName), "pak_generic") then BoolSkipElookup = True 'Trend Micro detection for possibly malicious executable files that are compressed using Win32 compression tools
  if instr(lcase(strVendorDetectionName), "artemis!") then BoolSkipElookup = True 
  if instr(lcase(strVendorDetectionName), "troj_spnr") then BoolSkipElookup = True 
  if instr(lcase(strVendorDetectionName), "gen:heur.") then BoolSkipElookup = True 'F-Secure Heuristic
  if instr(lcase(strVendorDetectionName), "gen:trojan.heur.") then BoolSkipElookup = True 'F-Secure Heuristic
  if instr(lcase(strVendorDetectionName), "deepscan:generic.") then BoolSkipElookup = True 'F-Secure Heuristic
end if
if dictEncyclopediaNegative.exists(strAV_Vendor & "|" & strVendorDetectionName) then 
  BoolSkipElookup = True

end if

if BoolSkipElookup = False then
  select case strAV_Vendor
    case "Microsoft"
		strTmpEC_URLreturn = TIAprocess(DictMicrosoftEncyclopedia, strAV_Vendor, strVendorDetectionName, strMicrosoftLineE)
    case "TrendMicro"
		strTmpEC_URLreturn = TIAprocess(DictTrendMicroEncyclopedia, strAV_Vendor, strVendorDetectionName, strTrendMicroLineE)
    case "McAfee"
		strTmpEC_URLreturn = TIAprocess(DictMcAfeeEncyclopedia, "McAfee", strVendorDetectionName, strMcAfeeLineE)
    case "Sophos"
		strTmpEC_URLreturn = TIAprocess(DictSophosEncyclopedia, "Sophos", strVendorDetectionName, strSophoslineE)
    case "Symantec" 
        strTmpEC_URLreturn = CheckSymantecEncyclopedia(strVendorDetectionName) 'runs TIAprocess with filtering
    case "ESET-NOD32"
      strTmpEC_URLreturn = TIAprocess(DictESETEncyclopedia, "ESET-NOD32", strVendorDetectionName, strESETlineE)
    case "AntiVir"'Avira
		strTmpEC_URLreturn = TIAprocess(DictAviraEncyclopedia, "Avira", strVendorDetectionName, strAviralineE)
	case "Avira"
		strTmpEC_URLreturn = TIAprocess(DictAviraEncyclopedia, "Avira", strVendorDetectionName, strAviralineE)
    case "DrWeb"
		strTmpEC_URLreturn = TIAprocess(DictDrWebEncyclopedia, "DrWeb", strVendorDetectionName, strDrWeblineE)
    case "F-Secure"
		strTmpEC_URLreturn = TIAprocess(DictFSecureEncyclopedia, "F-Secure", strVendorDetectionName, strFSecurelineE)
    case "Panda"
		strTmpEC_URLreturn = TIAprocess(DictPandaEncyclopedia, "Panda", strVendorDetectionName, strPandaLineE)
	case "BitDefender"
		strTmpEC_URLreturn = TIAprocess(DictBitdefenderEncyclopedia, "Bitdefender", strVendorDetectionName, strBitdefenderLineE)
  end select
  Encyclopdia_Cache = strTmpEC_URLreturn 
end if
end function

'Process requests for ThreatIntelligenceAggregator.org
Function TIAprocess(objectDict, vendorName, strVendDetectionName, strVendLineOut)
Dim TIAURLreturn: TIAURLreturn = ""
if objectDict.exists(strVendDetectionName) then
  TIAURLreturn = objectDict.item(strVendDetectionName)
  strVendLineOut = "|" & strVendDetectionName

elseif dictEncyclopediaNegative.exists(vendorName & "|" & strVendDetectionName) then
	'previously looked up with no results
	exit function
else
  TIAURLreturn = CheckTIA(vendorName, strVendDetectionName)
  if TIAURLreturn = "Q" then
    'detection name is in API queue
    if boolEnableTIAqueue = True then
		TIAURLreturn = vendorName
		strtmpVendQueue = strtmpVendQueue & vendorName & "|" & strVendDetectionName & "õ"
	else
		TIAURLreturn = ""
	end if
  elseif TIAURLreturn <> "" then
        if TIAURLreturn = "ERROR" then exit function 'don't save anything 
		if objectDict.exists(strVendDetectionName) = False then 
             objectDict.add strVendDetectionName, TIAURLreturn
             LogData strCachePath & "\" & vendorName & ".dat", strVendDetectionName & "|" & TIAURLreturn, false
         end if
         strVendLineOut = "|" & strVendDetectionName
  else
      dictEncyclopediaNegative.add vendorName & "|" & strVendDetectionName, ""
      LogData strCachePath & "\EncyclopediaN.dat", vendorName & "|" & strVendDetectionName, false
  end if
end if   
if TIAURLreturn = "" or TIAURLreturn = "ERROR" or TIAURLreturn = vendorName then 
	if dictUrlOut.exists(vendorName & "|" & strVendDetectionName) = True then
				strThisScanResults = replace(strThisScanResults,  dictUrlOut.item(vendorName & "|" & strVendDetectionName) & vbtab & strVendDetectionName & " - " & vendorName & vbCrLf, "")
	else
		TIAURLreturn = "" 'vendor name was returned meaning there is no URL so return nothing
	end if
else
	strThisScanResults = replace(strThisScanResults,  dictUrlOut.item(vendorName & "|" & strVendDetectionName) & vbtab & strVendDetectionName & " - " & vendorName, dictUrlOut.item(vendorName & "|" & strVendDetectionName) & vbtab & strVendDetectionName & " - " & TIAURLreturn)
end if
TIAprocess = TIAURLreturn
wscript.sleep 5
end Function


Function CheckKeyWords(strKWcheck)
Dim strTmpKWreturn
Dim IntMalwareScore
Dim IntPUAScore
Dim IntGenericScore
Dim IntTmpGenScoreCompre
Dim arrayTmpCKeywords
Dim strTmpMKWreturn
Dim strTmpHkTlKWreturn
Dim intTmpScoreAmp
strKWcheck = lcase(strKWcheck)
strTmpKWreturn = ""
strTmpMKWreturn = ""

strTmpMKWreturn = MalwareKeyWordNames(strKWcheck)

if instr(strTmpMKWreturn, "|") then
  arrayTmpCKeywords = Split(strTmpMKWreturn, "|")
  IntMalwareScore = IntMalwareScore + ubound(arrayTmpCKeywords)
else
  IntMalwareScore = 0
end if

'hacker tool detections
strTmpHkTlKWreturn = graywareKeyWords(lcase(strKWcheck))

'Use VTnameDetect to check against hacker tool names
strTmpPUAName =  VTnameDetect(lcase(strKWcheck), 1)
if strTmpPUAName <> "" and strTmpHkTlKWreturn <> "" then 
  if DictPUANames.exists(strTmpPUAName) = False then 
    strTmpHkTlKWreturn = strTmpHkTlKWreturn & "|" & strTmpPUAName
  end if
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", "strTmpHkTlKWreturn=" & strTmpHkTlKWreturn, false
if instr(strTmpHkTlKWreturn, "|") then
  arrayTmpCKeywords = Split(strTmpHkTlKWreturn, "|")
  IntHkTlScore = ubound(arrayTmpCKeywords)
else
  IntHkTlScore = 0
end if
'if strTmpPUAName <> "" then  IntHkTlScore = IntHkTlScore + 1

'generic detections
IntGenericScore = GenericKeyWords(lcase(strKWcheck))

'possible specific detections
if IntGenericScore = 0 and IntMalwareScore = 0 then 'if no generic detection check for malicious names
    IntMalwareScore = MalwareKeyWordScore(strKWcheck)
end if

if IntHkTlScore = 0 then
  'PUP/PUA
  strTmpPUAName =  PUAKeyWords(lcase(strKWcheck))
  if strTmpPUAName <> "" then strTmpKWreturn = strTmpPUAName
  strTmpPUAName = ""
  'Use VTnameDetect to check against PUA names
  strTmpPUAName =  VTnameDetect(lcase(strKWcheck), 2)
  if strTmpPUAName <> "" then strTmpKWreturn = strTmpKWreturn & "|" & strTmpPUAName
end if
'score PUA/PUP
if instr(strTmpKWreturn, "|") then
  arrayTmpCKeywords = Split(strTmpKWreturn, "|")
  IntPUAScore = ubound(arrayTmpCKeywords)
  if strTmpPUAName <> "" then  IntPUAScore = IntPUAScore + 1
else
  IntPUAScore = 0
end if

if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", intHashDetectionsLineE & "|Before Amplification score|" & IntMalwareScore & "|" & IntGenericScore & "|" & IntPUAScore & "|" & IntHkTlScore & "|" & IntTmpAdjustedMalScore, false

'decrease score for whitelist detection (Bkav:W32.WhiteListMZ)
if instr(strKWcheck, "whitelist") then
  IntMalwareScore = IntMalwareScore -1
  IntGenericScore = IntGenericScore -1
end if

'amplify score based on detection names
for each strUniqueDname in DicTmpDnames
  'LogData strDebugPath & "\dnames.log", strUniqueDname & "|" & DicTmpDnames.item(strUniqueDname) , false
  if instr(strKWcheck, strUniqueDname) then
    'check detection name dict score
    if IsNumeric(DicTmpDnames.item(strUniqueDname)) = True then
		if 5 < DicTmpDnames.item(strUniqueDname) then
		  intTmpScoreAmp = 4
		elseif 4 < DicTmpDnames.item(strUniqueDname) then
		  intTmpScoreAmp = 3
		elseif 3 < DicTmpDnames.item(strUniqueDname) then
		  intTmpScoreAmp = 2
		elseif 2 < DicTmpDnames.item(strUniqueDname) then
		  intTmpScoreAmp = 1
		end if
    else
		logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " DicTmpDnames.item(" & strUniqueDname & ") is not numeric",False 
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug.txt" & "" & ".txt", Date & " " & Time & " DicTmpDnames.item(" & strUniqueDname & ") is not numeric", false
	end if	

    if IntPUAScore > 0 then 
      if IntHkTlScore > 0 then
        IntHkTlScore = IntHkTlScore + intTmpScoreAmp
      else
        IntPUAScore = IntPUAScore + intTmpScoreAmp
      end if
    elseif IntMalwareScore > 0 then
      IntMalwareScore = IntMalwareScore + intTmpScoreAmp    
    elseif IntHkTlScore > 0 then
        IntHkTlScore = IntHkTlScore + intTmpScoreAmp      
    end if
  end if
next

'generic detection (appended to end of detection name so may fall into other categories)
if IntPUAScore = 0 and IntMalwareScore =0 and IntGenericScore =0 and IntHkTlScore = 0 and instr(strKWcheck, "!eldorado") then
  IntTmpGenericScore = 1

elseif IntPUAScore > 0 then 'if a PUA ensure no other score for this name exists 
  IntMalwareScore =0 
  IntGenericScore =0
elseif IntGenericScore > 0 then 'if a generic detection no other score for this name
  IntMalwareScore =0 
  IntPUAScore =0
end if

if IntPUAScore = 0 and IntMalwareScore =0 and IntGenericScore =0 and IntHkTlScore = 0 then IntMalwareScore = 1

'IntPUAScore = (IntPUAScore - IntMalwareScore)

intTmpMalScore = intTmpMalScore + IntMalwareScore
IntTmpPUA_Score = IntTmpPUA_Score + IntPUAScore
IntTmpGenericScore = IntTmpGenericScore + IntGenericScore 
IntTmpHkTlScore = IntTmpHkTlScore + IntHkTlScore
if intVTpositiveDetections = 1 then 'if only one vendor detection don't allow for any amplification of the scores
  if intTmpMalScore > 1 then intTmpMalScore = 1
  if IntTmpGenericScore > 1 then IntTmpGenericScore = 1
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", intHashDetectionsLineE & "|Building score|" & intTmpMalScore & "|" & IntTmpGenericScore & "|" & IntTmpPUA_Score & "|" & IntTmpHkTlScore & "|" & IntTmpAdjustedMalScore, false

CheckKeyWords = strTmpMKWreturn & "|" & strTmpKWreturn 
end function


Function PUAKeyWords(strTmpKWPUA)
Dim strPUAKWreturn
if instr(strTmpKWPUA, "pua") then strPUAKWreturn = strPUAKWreturn & "|" & "pua"
if instr(strTmpKWPUA, "pup") then strPUAKWreturn = strPUAKWreturn & "|" & "pup"
if instr(strTmpKWPUA, "pe:puf") then 
	strPUAKWreturn = strPUAKWreturn & "|" & "pe:puf" 'Rising potentially unwanted file
elseif instr(strTmpKWPUA, "puf.") then 
	strPUAKWreturn = strPUAKWreturn & "|" & "puf" 'Rising potentially unwanted file
end if
if instr(strTmpKWPUA, "softwarebundler") then strPUAKWreturn = strPUAKWreturn & "|" & "bundler"
if instr(strTmpKWPUA, "signed-adware") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "signed-adware"
elseif instr(strTmpKWPUA, "adware") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "adware"
elseif instr(strTmpKWPUA, "adw_") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "adw_"
elseif instr(strTmpKWPUA, "[adw]") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "adw_"
  elseif instr(strTmpKWPUA, "win32:adware") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "win32:adware"
  end if
if instr(strTmpKWPUA, "unwanted-program") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "unwanted-program"
elseif instr(strTmpKWPUA, "unwanted") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "unwanted" 
elseif instr(strTmpKWPUA, "program") then 
  strPUAKWreturn = strPUAKWreturn & "|" & "program" 
  end if  
if instr(strTmpKWPUA, ".optional.") then strPUAKWreturn = strPUAKWreturn & "|" & "optional"
if instr(strTmpKWPUA, "toolbar") then strPUAKWreturn = strPUAKWreturn & "|" & "toolbar"
if instr(strTmpKWPUA, "application.bundler") then strPUAKWreturn = strPUAKWreturn & "|" & "application.bundler"
if instr(strTmpKWPUA, "not-a-virus") then strPUAKWreturn = strPUAKWreturn & "|" & "not-a-virus"
if instr(strTmpKWPUA, "not malicious") then strPUAKWreturn = strPUAKWreturn & "|" & "not malicious"
if instr(strTmpKWPUA, "keygen") then strPUAKWreturn = strPUAKWreturn & "|" & "keygen"
if instr(strTmpKWPUA, "riskware") then strPUAKWreturn = strPUAKWreturn & "|" & "riskware"
if instr(strTmpKWPUA, "crack") then strPUAKWreturn = strPUAKWreturn & "|" & "Crack"
if instr(strTmpKWPUA, "android") then strPUAKWreturn = strPUAKWreturn & "|" & "android"
if instr(strTmpKWPUA, "applicunwnt") then strPUAKWreturn = strPUAKWreturn & "|" & "applicunwnt"
if instr(strTmpKWPUA, "downware") then strPUAKWreturn = strPUAKWreturn & "|" & "downware"
if instr(strTmpKWPUA, "game/") then strPUAKWreturn = strPUAKWreturn & "|" & "game/" 'Avira
PUAKeyWords = strPUAKWreturn
end function


Function ParseVTScanDate(strVTresponseText)
Dim strTmpVTDateTime

if instr(strVTresponseText, chr(34) & "scan_date" & chr(34) & ": ") then
  arrayPVTScanDate = split(strVTresponseText, chr(34) & "scan_date" & chr(34) & ": ")

    strTmpVTDateTime = getdata(arrayPVTScanDate(1), Chr(34), Chr(34))
end if
ParseVTScanDate = strTmpVTDateTime
end function

Function ParseVT_v3ScanDate(strVTresponseText)
	returnDate =  getdata(strVTresponseText, ",", "last_analysis_date" &  Chr(34) & ": ")
	if isnumeric(returnDate) = True then
		returnDate = EpochConvert(returnDate)
	end If
	dateFirstSeen =  getdata(strVTresponseText, ",", "first_submission_date" &  Chr(34) & ": ")
	If IsNumeric(dateFirstSeen) = True Then
		tmpDFS = EpochConvert(dateFirstSeen)
		SetDateFirstSeen tmpDFS
	End If	
	
	ParseVT_v3ScanDate = returnDate
end function

function ReturnFamilyName(strDetectNameSection)
if dictFamilyNames.exists(strDetectNameSection) then
	ReturnFamilyName = dictFamilyNames.item(strDetectNameSection)
else
	ReturnFamilyName = ""
end if
end function


Function VTnameDetect(strTmpMalDname, IntCompare) 'attempts to resolve the detection name
'add something to track matches of detection names for excel reporting
Dim strTmpVTNDreturn
Dim strVTNDreturn
Dim strArrayNBreaks
Dim arrayNamebreaks
Dim strTmpDatFileSave
strArrayNBreaks = strTmpMalDname
If instr(strArrayNBreaks,".") then
 strArrayNBreaks = replace(strArrayNBreaks, ".", "|")
end if
if instr(strArrayNBreaks, "/") then
  strArrayNBreaks = replace(strArrayNBreaks, "/", "|")
end if
if instr(strArrayNBreaks, "!") then
  strArrayNBreaks = replace(strArrayNBreaks, "!", "|")
end if
if instr(strArrayNBreaks, "_") then
  if instr(strArrayNBreaks, "exploit.") = 0 then
	strArrayNBreaks = replace(strArrayNBreaks, "_", "|")
  else
	strArrayNBreaks = replace(strArrayNBreaks, "exploit.", "exploit-")'Replacement for ClamAV to match McAfee
	strArrayNBreaks = replace(strArrayNBreaks, "-", "|")
	strArrayNBreaks = replace(strArrayNBreaks, "_", "-")
  end if
end if
if instr(strArrayNBreaks, " ") then
  strArrayNBreaks = replace(strArrayNBreaks, " ", "|")
end if
if instr(strArrayNBreaks, ":") then
  strArrayNBreaks = replace(strArrayNBreaks, ":", "|")
end if
if instr(strArrayNBreaks, "-") then
  if instr(strArrayNBreaks, "exploit-") = 0 then
	if instr(strArrayNBreaks, "cve-") = 0 then
		strArrayNBreaks = replace(strArrayNBreaks, "-", "|")
	end if
  else
	strArrayNBreaks = replace(strArrayNBreaks, "exploit-", "exploit|") 'McAfee style and replacement for ClamAV to match McAfee
  end if
end if
 if BoolDebugTrace = True then LogData strDebugPath & "\VTDnames.log", strTmpMalDname , false
 if BoolDebugTrace = True then LogData strDebugPath & "\labels.log",strTmpMalDname, false
if instr(strArrayNBreaks, "|") then  
  arrayNamebreaks = split(strArrayNBreaks, "|")

  for each strTmpDnameSection in arrayNamebreaks
	if left(strTmpDnameSection, 3) = "cve" then 
	  strTmpDnameSection = CVE_Format(strTmpDnameSection)
	end if
	'attempt to use the most common detection name
	strTmpRfamName = ReturnFamilyName(strTmpDnameSection)
	if  strTmpRfamName <> "" then
		strTmpDnameSection = strTmpRfamName
	end if
	if IntCompare = 0 then 'common name detection
		if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "strTmpDnameSection=" & strTmpDnameSection, false
		strTmpVTNDreturn = VTnameParse(strTmpDnameSection) 'Filter out generic names we don't want used
        if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "strTmpVTNDreturn=" & strTmpVTNDreturn, false
		'builds array that is returned for common name identification
		if strTmpVTNDreturn <> "" then 
          if strVTNDreturn = "" then
            strVTNDreturn = strTmpVTNDreturn          
          else
            strVTNDreturn = strVTNDreturn & "|" & strTmpVTNDreturn
          end if
        end if
		
      elseif IntCompare = 1 then 'Hackertool processing
        if DictHktlNames.exists(strTmpDnameSection) = True then strVTNDreturn = strTmpDnameSection
      elseif IntCompare = 2 then 'PUA processing
        if DictPUANames.exists(strTmpDnameSection) = True then 
          if DictHktlNames.exists(strTmpDnameSection) = True then'Remove detection name from pup.dat
            strTmpDatFileSave = RemoveTextline(strCachePath & "\PUP.dat",strTmpDnameSection)
            if BoolDebugTrace = True then LogData strDebugPath & "\VTDnames.log", "Removed PUP entry:" & strTmpDatFileSave & "|" & strTmpDnameSection, False
            LogoverwriteData strCachePath & "\PUP.dat", strTmpDatFileSave, false
            DictPUANames.Remove(strTmpDnameSection)
          elseif IntTmpHkTlScore > IntTmpPUA_Score +1 then' add detection name to hktl.dat
			if BoolDebugTrace = True then LogData strDebugPath & "\VTDnames.log", "IntTmpHkTlScore > IntTmpPUA_Score:" & IntTmpHkTlScore & "|" & IntTmpPUA_Score, False
			if BoolDebugTrace = True then LogData strDebugPath & "\VTDnames.log", "Added HKTL entry:" & strTmpDatFileSave & "|" & strTmpDnameSection, False
            DictHktlNames.add strTmpDnameSection, IntTmpHkTlScore
            LogData strCachePath & "\hktl.dat", strTmpDnameSection & "|" & IntTmpHkTlScore, false
          else
            strVTNDreturn = strTmpDnameSection   
          end if
        end if
      end if
  next          
elseif IntCompare = 0 then 'if no parts identified in detection name
	if left(strTmpMalDname, 3) = "cve" then 'check if CVE and update
	  strVTNDreturn = CVE_Format(strTmpMalDname)
	else
		strVTNDreturn = strTmpMalDname
	end if
elseif IntCompare = 1 then
  if DictHktlNames.exists(strTmpMalDname) = True then strVTNDreturn = strTmpMalDname  

elseif IntCompare = 2 then
  if DictPUANames.exists(strTmpMalDname) = True then strVTNDreturn = strTmpMalDname  
end if
VTnameDetect = strVTNDreturn
end function


Function CVE_Format(strDnameCVE)
DIm strReturnCVE
if instr(strDnameCVE, "-") > 0 then
  if mid(strDnameCVE,4,1) = "-" then
    strReturnCVE = strDnameCVE
  else
    strReturnCVE = "cve-" & right(strDnameCVE,9)
  end if
elseif len(strDnameCVE) = 9 then
  strReturnCVE = "cve-20" & mid(strDnameCVE,4,2) & "-" & right(strDnameCVE,4)
elseif len(strDnameCVE) = 11 then
  strReturnCVE = "cve-" & mid(strDnameCVE,4,4) & "-" & right(strDnameCVE,4)
else
  strReturnCVE = strDnameCVE
end if
CVE_Format = strReturnCVE
end function


'Filter out generic names we don't want used for common name detection
Function VTnameParse(StrTmpNamePart)
if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "StrTmpNamePart=" & StrTmpNamePart, false
if StrTmpNamePart <> "adware" and StrTmpNamePart <> "hfsadware" and StrTmpNamePart <> "not-a-virus" _ 
and StrTmpNamePart <> "application" and StrTmpNamePart <> "bundler" and StrTmpNamePart <> "toolbar" _
and StrTmpNamePart <> "riskware" and StrTmpNamePart <> "applicunwnt" and StrTmpNamePart <> "downware" _
and StrTmpNamePart <> "android" and StrTmpNamePart <> "keygen" and StrTmpNamePart <> "signed-adware" _
and StrTmpNamePart <> "unwanted-program" and StrTmpNamePart <> "unwanted" and StrTmpNamePart <> "crack" _
and StrTmpNamePart <> "potentially" and StrTmpNamePart <> "malicious)" and StrTmpNamePart <> "variant" _
and StrTmpNamePart <> "trojan" and StrTmpNamePart <> "generic" and StrTmpNamePart <> "generickd" _
and StrTmpNamePart <> "(cloud)" and StrTmpNamePart <> "behaveslike" and StrTmpNamePart <> "malicious" _
and StrTmpNamePart <> "score" and StrTmpNamePart <> "agent" and StrTmpNamePart <> "malware" _
and StrTmpNamePart <> "(high" and StrTmpNamePart <> "confidence)" and StrTmpNamePart <> "unsafe" _
and StrTmpNamePart <> "behavior" and StrTmpNamePart <> "confidence"  _
and StrTmpNamePart <> "risktool" and StrTmpNamePart <> "share" and StrTmpNamePart <> "remoteadmin" and _
StrTmpNamePart <> "daemon" and StrTmpNamePart <> "[pup]" and StrTmpNamePart <> "possible" and _
StrTmpNamePart <> "probably" and StrTmpNamePart <> "[adw]" and StrTmpNamePart <> "win32:adware" and _
isnumeric(StrTmpNamePart) = false then
	if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "Passed StrTmpNamePart=" & StrTmpNamePart, false
  if StrTmpNamePart <> "win32" and StrTmpNamePart <> "msil" and StrTmpNamePart <> "optional" and _ 
  StrTmpNamePart <> "(pua)" and StrTmpNamePart <> "riskware[risktool]" then
    if len(StrTmpNamePart) > 4 then
		if left(StrTmpNamePart, 3) = "cve" then 
		  StrTmpNamePart = CVE_Format(StrTmpNamePart)
		end if
	end if
	if BoolDebugTrace = True then LogData strDebugPath & "\labels.log",  "DetectionTypeKeywords(" & StrTmpNamePart & ") = " & DetectionTypeKeywords(StrTmpNamePart) , false
	if DetectionTypeKeywords(StrTmpNamePart) = 0 then 'remove detection types
		if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "GenericTypeKeywords(" & StrTmpNamePart & ") = " & GenericTypeKeywords(StrTmpNamePart) , false
		if GenericTypeKeywords(strTmpNamePart) = 0 then
			if len(StrTmpNamePart) > 4 then
				VTnameParse = StrTmpNamePart
			end if
		end if
	end if

  end if
end if
end function


Function GenericKeyWords(StrTmpKWG)
'specific generic detections should increase score for malware
'generic malware detections Symantec	Trojan.Bedep!gen1	
''SUPERAntiSpyware	Trojan.Agent/Gen-Bedep
'Virus.Win32.Cekar.gen (v)
Dim IntTmpGenericKWScore

IntTmpGenericKWScore = 0
if instr(StrTmpKWG, "generic") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "siggen") then 'DrWeb
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "gen") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if
if instr(StrTmpKWG, "packer") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "packed") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif instr(StrTmpKWG, "susppack") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif StrTmpKWG = "pak" then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
end if

if instr(StrTmpKWG, "et#") then 
	if right(StrTmpKWG, 1) = "%" Then
		IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
	end if
end if

if instr(StrTmpKWG, "kryptik") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "kazy") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "unclassifiedmalware") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "agent") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "artemis") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif instr(StrTmpKWG, "mikey") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "troj_spnr") then 'Trend Micro Smart Protection Network Reputation detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "trojan.adh.") then 'Symantec generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif instr(StrTmpKWG, "artemis!") then 'McAfee generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "eldorado") then 'generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif instr(StrTmpKWG, "malicious") then 'CrowdStrike generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "behaveslike") then 'generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "confidence") then 'CrowdStrike generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "wisdomeyes") then 'Baidu's generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "suspicious") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "suspected") then 'VBA32
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1  
elseif instr(StrTmpKWG, "[susp]") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "suspectcrc") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1 
elseif instr(StrTmpKWG, "graftor") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1 
elseif instr(StrTmpKWG, "symmi") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1 
elseif instr(StrTmpKWG, "dnascan") then 'CAT-QuickHeal generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "(classic)") then '(classic) Rising generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "(cloud)") then ' Rising generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "undefined") then ' Rising generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "(kcloud)") then ' Kingsoft generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
elseif instr(StrTmpKWG, "(rdm+)") then ' Rising generic detection
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1    
end if


if instr(StrTmpKWG, "reputation") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if

if instr(StrTmpKWG, "heuristic") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "sheur") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
elseif instr(StrTmpKWG, "heur]") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if

if instr(StrTmpKWG, "unsafe") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if
if instr(StrTmpKWG, "moderate") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if
if instr(StrTmpKWG, "filerepmalware") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if
if instr(StrTmpKWG, "filerepmalware") then 
  IntTmpGenericKWScore = IntTmpGenericKWScore + 1
end if


GenericKeyWords = IntTmpGenericKWScore
end function


Function GenericTypeKeywords(StrTmpKWG)
if BoolDebugTrace = True then LogData strDebugPath & "\labels.log", "dictGenericLabel.exists(" & StrTmpKWG & ") = " & dictGenericLabel.exists(StrTmpKWG), false
if dictGenericLabel.exists(StrTmpKWG) then
	  DetectionTypeTrack dictGenericLabel.item(StrTmpKWG)
	  GenericTypeKeywords = 1
else
	GenericTypeKeywords = 0
end if
end Function

Sub DetectionTypeTrack(strDtypeName)

if DictTypeNames.exists(strDtypeName) = false then 
  DictTypeNames.add strDtypeName, 0
else
  DictTypeNames.item(strDtypeName) = DictTypeNames.item(strDtypeName) + 1
end if  
end sub

Function DetectionTypeKeywords(StrTmpKWG)
'Common detection types
'will normalize to common type name
Dim IntTmpDTypeKWScore

IntTmpDTypeKWScore = 0
if left(StrTmpKWG, 10) = "downloader" then 
	if isnumeric(right(StrTmpKWG, len(StrTmpKWG) -10)) = True then 'Comodo
		DetectionTypeTrack "downloader"
	end if
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
elseif StrTmpKWG = "trojdownloader" then
  DetectionTypeTrack "downloader"

  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if
if left(StrTmpKWG, 7) = "downldr" then 
	if isnumeric(right(StrTmpKWG, len(StrTmpKWG) -7)) = True then 'F-Prot
		DetectionTypeTrack "downloader"
	end if
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
elseif StrTmpKWG = "dropper" then
	DetectionTypeTrack "downloader"

	IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
elseif instr(StrTmpKWG, "trojandwnldr") > 0 then
	if isnumeric(right(StrTmpKWG, len(StrTmpKWG) -10)) = True then 'Comodo
		DetectionTypeTrack "downloader"
	end if
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if

'ransomx - AVG/Avast
if instr(StrTmpKWG, "[ransom]") > 0 or instr(StrTmpKWG, "ransomx") > 0 or _ 
  instr(StrTmpKWG, "ransomheur") > 0 or instr(StrTmpKWG, "ransomcrypt") > 0 or _
instr(StrTmpKWG, "obfusransom") > 0 or instr(StrTmpKWG, "ransomx") > 0 or _
StrTmpKWG = "filelocker" then
	DetectionTypeTrack "ransomware"
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if

'some of the cryptocurrency ones need to be instr
if StrTmpKWG = "brocoiner" or StrTmpKWG = "bitcoinminer" or StrTmpKWG = "bitcoin" or _
StrTmpKWG = "btcminer" or StrTmpKWG = "coinminer" or StrTmpKWG = "coinhive" or _
StrTmpKWG = "monero" or StrTmpKWG = "litecoin" or StrTmpKWG = "peercoin" or _
StrTmpKWG = "feathercoin" or StrTmpKWG = "cryptocoinminer" or StrTmpKWG = "coinmine" or _
StrTmpKWG = "coinmin" or StrTmpKWG = "coinmi" or StrTmpKWG = "coinm" or _
StrTmpKWG = "webcoinminer" or StrTmpKWG = "wasmwebcoin" or StrTmpKWG = "miner" or _
StrTmpKWG = "powcointhen" Then
	DetectionTypeTrack "cryptocurrency_miner"
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if

if StrTmpKWG = "bds" or StrTmpKWG = "bck" or StrTmpKWG = "bkdr" then
	DetectionTypeTrack "backdoor"
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if

if StrTmpKWG = "banker" or StrTmpKWG = "bankerx" or StrTmpKWG = "trojan[banker]" or _
StrTmpKWG = "trojanbanker" then

	DetectionTypeTrack "banker"
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if
if left(StrTmpKWG, 6) = "banker" then 
	if isnumeric(right(StrTmpKWG, len(StrTmpKWG) -6)) = True then 
		DetectionTypeTrack "banker"
	end if
  IntTmpDTypeKWScore = IntTmpDTypeKWScore + 1
end if

DetectionTypeKeywords = IntTmpDTypeKWScore
end function


Function ExcludeKeywords(StrTmpKWG)'don't score these items as they are a descriptor  
if StrTmpKWG = "win64" then 
  IntTmpExcludeKWScore = IntTmpExcludeKWScore + 1
end if
end function


Function CheckBitDefenderEngines(strBDvendorNames)'http://www.av-comparatives.org/list-of-consumer-av-vendors-pc/
Dim boolCBDEreturn
Dim strTmpBDvendorNames
Dim StrTmpVendPosDet
StrTmpVendPosDet = Chr(34) & ": {" & Chr(34) & "detected" & Chr(34) & ": true"
strTmpBDvendorNames = lcase(strBDvendorNames)
boolCBDEreturn = False

if instr(strTmpBDvendorNames, "ad-aware" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "avg" & StrTmpVendPosDet) then boolCBDEreturn = True 'Avast purchased AVG
if instr(strTmpBDvendorNames, "fireeye" & StrTmpVendPosDet) then boolCBDEreturn = True 'multiengine - bitdefender
if instr(strTmpBDvendorNames, "bitdefender" & StrTmpVendPosDet) then boolCBDEreturn = True 'multiengine - bitdefender
if instr(strTmpBDvendorNames, "Bitdefendertheta" & StrTmpVendPosDet) then boolCBDEreturn = True 'bitdefender engine
if instr(strTmpBDvendorNames, "f-secure" & StrTmpVendPosDet) then boolCBDEreturn = True 'moved to Avira
if instr(strTmpBDvendorNames, "gdata" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "microworld-escan" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "emsisoft" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "escan" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "nprotect" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "alyac" & StrTmpVendPosDet) then boolCBDEreturn = True 'multiengine - bitdefender
if instr(strTmpBDvendorNames, "ad-aware" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "arcabit" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "cat-quickheal" & StrTmpVendPosDet) then boolCBDEreturn = True
If instr(strTmpBDvendorNames, "tencent" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "totaldefense" & StrTmpVendPosDet) then boolCBDEreturn = True
If instr(strTmpBDvendorNames, "Qihoo-360" & StrTmpVendPosDet) then boolCBDEreturn = True
if instr(strTmpBDvendorNames, "vipre" & StrTmpVendPosDet) then boolCBDEreturn = True
CheckBitDefenderEngines = boolCBDEreturn
 if BoolDebugTrace = True then LogData strDebugPath & "\bitdefen.log", boolCBDEreturn & "|" & strTmpBDvendorNames , false
end function


Function MalwareKeyWordScore(StrTmpKWM)
Dim IntTmpMalwareScore: IntTmpMalwareScore = 0
Dim strKWMalware: strKWMalware = lcase(StrTmpKWM)

  if instr(strKWMalware, "trojan") then 
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value
  elseif instr(strKWMalware, "troj") then 
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value    
  elseif instr(strKWMalware, "trj") then 
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value   
  elseif instr(strKWMalware, "virus") then 
    if instr(strKWMalware, "not-a-virus") = 0 then _
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value  
   elseif instr(strKWMalware, "malware") then 
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value 
   elseif instr(strKWMalware, "mal/") then 
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value     
  elseif left(strKWMalware, 3) = "cve" then 
	IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value
  elseif instr(strKWMalware, "malware@#") then 'Comodo
    IntTmpMalwareScore = IntTmpMalwareScore + 1 'add extra to value     
  end if
MalwareKeyWordScore = IntTmpMalwareScore
end function



Function MalwareKeyWordNames(StrTmpKW_M)
Dim strTmpMalKWreturn
if instr(StrTmpKW_M, "backdoor") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "backdoor"
elseif instr(StrTmpKW_M, "bkdr") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bdoor"
elseif instr(StrTmpKW_M, "bkdr") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bkdr"
elseif instr(StrTmpKW_M, "bck/") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bck/" 
elseif instr(StrTmpKW_M, "bds/") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bds/"
elseif instr(StrTmpKW_M, "bot") then 'avoid backdoor.bot scoring too much
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bot"
end if  
if instr(StrTmpKW_M, "boot_") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "boot_"
if instr(StrTmpKW_M, "rat") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "rat"
if instr(StrTmpKW_M, "pws:") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "pws:"
if instr(StrTmpKW_M, "keylog") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "keylog"
if instr(StrTmpKW_M, "tspy_") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "tspy_"
elseif instr(StrTmpKW_M, "smsspy") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "smsspy" 
elseif instr(StrTmpKW_M, "spy") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "spy"  
end if
if instr(StrTmpKW_M, "infostealer") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "infostealer"
elseif instr(StrTmpKW_M, "smsstealer") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "smsstealer"
elseif instr(StrTmpKW_M, "smstealer") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "smstealer"  
elseif instr(StrTmpKW_M, "stealer") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "stealer"
end if
if instr(StrTmpKW_M, "worm") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "worm"
if instr(StrTmpKW_M, "rootkit") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "rootkit"
if instr(StrTmpKW_M, "rkit") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "rkit"
if instr(StrTmpKW_M, "phish") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "phish"
if instr(StrTmpKW_M, "inject") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "inject"
if instr(StrTmpKW_M, "hack") then 
  if instr(StrTmpKW_M, "keygen") = 0 and instr(StrTmpKW_M, "agent") = 0 then _
   strTmpMalKWreturn = strTmpMalKWreturn & "|" & "hack"
end if
if instr(StrTmpKW_M, "vbs_") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "vbs_"
'if instr(StrTmpKW_M, "hktl_") then strTmpMalKWreturn = strTmpMalKWreturn & "|" & "hktl_"
if instr(StrTmpKW_M, "banker") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "banker"
elseif instr(StrTmpKW_M, "bank") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "bank" 
end if
if instr(StrTmpKW_M, "heuristic") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "heuristic"
elseif instr(StrTmpKW_M, "heur") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "heur" 
end if
if instr(StrTmpKW_M, "downloader") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "downloader"
elseif instr(StrTmpKW_M, "download") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "download"
elseif instr(StrTmpKW_M, "downldr") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "downldr"
elseif instr(StrTmpKW_M, "downware") = 0 then 
  if instr(StrTmpKW_M, "down") then _ 
   strTmpMalKWreturn = strTmpMalKWreturn & "|" & "down"   
end if
if instr(StrTmpKW_M, "ransom") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "ransom"
end if
if instr(StrTmpKW_M, "virtool") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "virtool"
end if
if instr(StrTmpKW_M, "exploit") then 
  strTmpMalKWreturn = strTmpMalKWreturn & "|" & "exploit"
end if
MalwareKeyWordNames = strTmpMalKWreturn
end function


Function graywareKeyWords(StrTmpKWGray)
Dim strTmpGrayKWreturn
Dim StrKWGray
StrKWGray = lcase(StrTmpKWGray)
if instr(StrKWGray, "hacktool") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "hacktool"
elseif instr(StrKWGray, "nettool") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "nettool"
elseif instr(StrKWGray, "pwcrack") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "pwcrack"
elseif instr(StrKWGray, "htool") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "htool"
elseif instr(StrKWGray, "monitoringtool") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "monitoringtool"   
elseif instr(StrKWGray, "risktool") then 'has lots of pup/pua stuff that isn't a hacker tool
  'strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "risktool"    
elseif instr(StrKWGray, "toolbar") = 0 and instr(StrKWGray, "fraudtool") = 0 and instr(StrKWGray, "tool") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "tool"
end if
if instr(StrKWGray, "hktl_") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "hktl_"
if instr(StrKWGray, "spr/") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "spr/" 'avira Security or Privacy Risk
if instr(StrKWGray, "Abuse-Worry/") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "Abuse-Worry/" 'nprotect commonly used programs and commercial programs such as keyloggers which can be used are exploited. 
if instr(StrKWGray, "applicunsaf") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "ApplicUnsaf"
if instr(StrKWGray, "potentially unsafe") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "potentially unsafe"
elseif instr(StrKWGray, "unsafe") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "unsafe"
end if
if instr(StrKWGray, "remoteadmin") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "RemoteAdmin"
if instr(StrKWGray, "remote-access") then strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "Remote-Access"

if instr(StrKWGray, "win-appcare") then 
  'strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "Win-AppCare" 'AhnLab-V3 has pup/pua stuff that isn't a hacker tool
end if
if instr(StrKWGray, "keylogger") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "keylogger"
elseif instr(StrKWGray, "keylog") then 
  strTmpGrayKWreturn = strTmpGrayKWreturn & "|" & "keylog"
end if
graywareKeyWords = strTmpGrayKWreturn
end function


Sub IPSinkholeCheck(strIP2check,strSinkholeIP, strSinkholeText)
if strIP2check = strSinkholeIP then 
	strTmpSinkHole = strSinkholeText
end if
end sub


sub subReverseDNSwithSinkhole(strIPRevLookup, DNSserverIP)
' Emerging Threats 
'
' This distribution may contain rules under two different licenses. 
'
'  Rules with sids 100000000 through 100000908 are under the GPLv2.
'  A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html
'
'  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License 
'  as follows:
'
'*************************************************************
'  Copyright (c) 2003-2017, Emerging Threats
'  All rights reserved.
'  
'  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
'  following conditions are met:
'  
'  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
'    disclaimer.
'  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
'    following disclaimer in the documentation and/or other materials provided with the distribution.
'  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 
'    from this software without specific prior written permission.
'  
'  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 
'  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
'  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
'  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
'  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
'  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
'  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
'
'*************************************************************
'
'
'
'
if left(strIPRevLookup, 9) = "195.22.26" then
	intLastOctet = right(strIPRevLookup,3)
	if isnumeric(intLastOctet) then
		if intLastOctet > 192 then 'https://lists.emergingthreats.net/pipermail/emerging-sigs/2014-November/025076.html
			strTmpSinkHole = "|195.22.26.192/26 - AnubisNetworks Sinkhole"	'There are IP addresses in this range that aren't used for Sinkholes
		end if
	end if
elseif left(strIPRevLookup, 9) = "195.22.28" then '195.22.28.193 - 195.22.28.222
	intLastOctet = right(strIPRevLookup,3)
	if isnumeric(intLastOctet) then
		if intLastOctet > 192 and intLastOctet < 223 then 
			strTmpSinkHole = "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"	'There are IP addresses in this range that aren't used for Sinkholes
		end if
	end if

end if
if left(strIPRevLookup, 9) = "199.2.137." then
	strTmpSinkHole = "|ET TROJAN DNS Reply Sinkhole - Microsoft - 199.2.137.0/24"
elseif left(strIPRevLookup, 9) = "207.46.90." then
	strTmpSinkHole = "|ET TROJAN DNS Reply Sinkhole - Microsoft - 207.46.90.0/24"
elseif left(strIPRevLookup, 9) = "204.95.99." then
	strTmpSinkHole = "|ET TROJAN DNS Reply Sinkhole Microsoft NO-IP Domain"	
end if

IPSinkholeCheck strIPRevLookup, "142.0.36.234", "|ET DNS Reply Sinkhole FBI Zeus P2P 1 - 142.0.36.234"
IPSinkholeCheck strIPRevLookup, "106.187.96.49", "|ET DNS Reply Sinkhole - 106.187.96.49 blacklistthisdomain.com"
IPSinkholeCheck strIPRevLookup, "148.81.111.111", "|ET DNS Reply Sinkhole - sinkhole.cert.pl 148.81.111.111"
IPSinkholeCheck strIPRevLookup, "198.61.227.6", "|ET DNS Reply Sinkhole - Georgia Tech (1)"
IPSinkholeCheck strIPRevLookup, "50.62.12.103", "|ET DNS Reply Sinkhole - Georgia Tech (2)"
IPSinkholeCheck strIPRevLookup, "50.57.148.87", "|ET TROJAN Connection to Georgia Tech Sinkhole IP (Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "166.78.144.80", "|ET TROJAN Connection to Georgia Tech Sinkhole IP (Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "82.165.25.210", "|ET DNS Reply Sinkhole - 1and1 Internet AG"
IPSinkholeCheck strIPRevLookup, "82.165.25.167", "|ET DNS Reply Sinkhole - German Company"
IPSinkholeCheck strIPRevLookup, "176.31.62.76", "|ET DNS Reply Sinkhole - Zinkhole.org"
IPSinkholeCheck strIPRevLookup, "91.233.244.106", "|ET DNS Reply Sinkhole - Dr. Web"
IPSinkholeCheck strIPRevLookup, "212.227.20.19", "|ET TROJAN Connection to 1&1 Sinkhole IP (Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "91.233.244.106", "|ET TROJAN Connection to Dr Web Sinkhole IP(Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "193.166.255.171", "|ET TROJAN Connection to Fitsec Sinkhole IP (Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "148.81.111.111", "|ET TROJAN Connection to a cert.pl Sinkhole IP (Possible Infected Host)"
IPSinkholeCheck strIPRevLookup, "161.69.13.44", "|ET TROJAN DNS Reply Sinkhole - IP - 161.69.13.44"
IPSinkholeCheck strIPRevLookup, "46.244.21.4", "|ET TROJAN Vobus/Beebone Sinkhole DNS Reply"
IPSinkholeCheck strIPRevLookup, "95.211.172.143", "|ET TROJAN Kaspersky Sinkhole DNS Reply"
IPSinkholeCheck strIPRevLookup, "23.253.46.64", "|ET TROJAN Wapack Labs Sinkhole DNS Reply"
IPSinkholeCheck strIPRevLookup, "131.253.18.11", "|ET TROJAN DNS Reply Sinkhole - Microsoft - 131.253.18.11-12"
IPSinkholeCheck strIPRevLookup, "131.253.18.12", "|ET TROJAN DNS Reply Sinkhole - Microsoft - 131.253.18.11-12"
IPSinkholeCheck strIPRevLookup, "195.38.137.100", "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"
IPSinkholeCheck strIPRevLookup, "195.22.4.21", "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"
IPSinkholeCheck strIPRevLookup, "195.157.15.100", "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"
IPSinkholeCheck strIPRevLookup, "212.61.180.100", "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"
IPSinkholeCheck strIPRevLookup, "212.61.180.100", "|ET TROJAN AnubisNetworks Sinkhole SSL Cert lolcat - specific IPs"
IPSinkholeCheck strIPRevLookup, "87.106.18.141", "|1and1 Internet AG Sinkhole"

' End Emerging Threats rules
 
 strRevDNS = "|" & nslookup_Return(strIPRevLookup & " " & DNSserverIP)
 if strTmpSinkHole = "|" and instr(lcase(strRevDNS), "sinkhole") or instr(lcase(strRevDNS), "snkhole") then 'only update if a sinkhole isn't already known. DNS sinkhole will provide more information that IP sinkhole.
  strTmpSinkHole = "|X"
 end if
end sub


sub subReverseDNSCachewithSinkhole(strDomainRevLookup)
 if strRevDNS = "|" then
  sSQL = "SELECT RevDomain from DomainVend WHERE DomainName = ?"
  strRevDNS = "|" & ReturnSQLiteItem(sSQL, strDomainRevLookup, "DomainVend")
 end if
 if strTmpSinkHole = "|" and instr(lcase(strRevDNS), "sinkhole") or instr(lcase(strRevDNS), "snkhole") then 'only update if a sinkhole isn't already known. DNS sinkhole will provide more information that IP sinkhole.
  strTmpSinkHole = "|X"
 end if
end Sub


Sub MalShareHashLookup(strHashVal)
  strtmpResults = checkMalShare(strHashVal)
  if strtmpResults <> "" then
    strThisScanResults = strThisScanResults & strtmpReslts & vbcrlf
  end if  
end sub

Function checkMalShare(strMalShare_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
dim strAssocWith
strAVEurl = "http://malshare.com/api.php?api_key=" & strMalShareAPIKey & "&action=details&hash="
 if ishash(strMalShare_ScanItem) and BoolDisableCacheLookup = False then
  strMSresponseText = CacheLookup("", "\malshare\", strMalShare_ScanItem, intHashCacheThreashold)
  'msgbox "cachestrMSresponseText=" & strMSresponseText
 end if
if strMSresponseText = "" then
  objHTTP.open "GET", strAVEurl & strMalShare_ScanItem, False
 
  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " MalShare lookup failed with HTTP error. - " & err.description,False 
      exit function 
    end if
  on error goto 0  

  if BoolDebugTrace = True then logdata strDebugPath & "\malshare" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  strMSresponseText = objHTTP.responseText
end if
if len(strMSresponseText) > 0 then
  if BoolDisableCaching = False then CacheLookup strMSresponseText, "\malshare\", strMalShare_ScanItem, intHashCacheThreashold
  if instr(strMSresponseText, "Sample not found by hash ") then
    'hash not found
    strTmpMalShareLineE = "|"
  else
    if instr(strMSresponseText, "SHA1") then 
      checkMalShare = "MalShare has a copy of the file for hash " & strMalShare_ScanItem
      strTmpMalShareLineE = "|X"
    end if
  end if
else
    strTmpMalShareLineE = "|"
end if

 
Set objHTTP = Nothing
end Function



function UDate(oldDate)
    UDate = DateDiff("s", "01/01/1970 00:00:00", oldDate)
end function

Sub ExitExcel()
if BoolUseExcel = True then
  objExcel.DisplayAlerts = False
  objExcel.quit
end if
end sub


Function checkCarBlack(strCarBlack_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
dim strAssocWith
Dim strCBresponseText
Dim strtmpCB_Fpath

if BoolDisableCBCachLookup = false then strCBresponseText = CacheLookup("", "\CB\", strCarBlack_ScanItem, intHashCacheThreashold)
if strCBresponseText = "" then
  strAVEurl = StrBaseCBURL & "/api/v1/binary/" & strCarBlack_ScanItem & "/summary"

  objHTTP.open "GET", strAVEurl, False

  objHTTP.setRequestHeader "X-Auth-Token", strCarBlackAPIKey 
    

  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " CarBlack lookup failed with HTTP error " & err.number & " - " & err.description,False 
      exit function 
    end if
  on error goto 0  

  if BoolDebugTrace = True then logdata strDebugPath & "\CarBlack" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  strCBresponseText = objHTTP.responseText
end if

if len(strCBresponseText) > 0 then
  if BoolDisableCaching = False then CacheLookup strCBresponseText, "\CB\", strCarBlack_ScanItem, intHashCacheThreashold
  'logdata strDebugPath & "cb.log", strCBresponseText, false
  if instr(strCBresponseText, "Sample not found by hash ") then
    'hash not found
  elseif instr(strCBresponseText, "400 Bad Request") then
    msgbox "Disabling Carbon Black queries. Problem connecting to server: " & strAVEurl 
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Disabling Carbon Black queries. Problem connecting to server: " & strAVEurl ,False 
    BoolUseCarbonBlack = False
  else
    if instr(strCBresponseText, "md5") then 
      checkCarBlack = "Carbon Black has a copy of the file for hash " & strCarBlack_ScanItem
      
      strCBfilePath = getdata(strCBresponseText, "]", "observed_filename" & Chr(34) & ": [")
      strCBfilePath = replace(strCBfilePath,chr(10),"")
      strCBfilePath = RemoveTLS(strCBfilePath)
      strCBfilePath = getdata(strCBfilePath, chr(34),chr(34))'just grab the fist file path listed
      if instr(strCBresponseText, "digsig_publisher") then 
        strCBdigSig = getdata(strCBresponseText, chr(34), "digsig_publisher" & Chr(34) & ": " & Chr(34))
        strCBdigSig = replace(strCBdigSig,chr(10),"")
      else
        'not signed 
      end if
      if instr(strCBresponseText, "signed" & Chr(34) & ": " & Chr(34) & "Signed") = 0 and instr(strCBresponseText, "signed" & Chr(34) & ": " & Chr(34) & "Unsigned") = 0 then
        'problem with sig
        strCBdigSig = getdata(strCBresponseText, chr(34), "signed" & Chr(34) & ": " & Chr(34)) & " - " & strCBdigSig
      end if 
      strCBcompanyName = getdata(strCBresponseText, chr(34), "company_name" & Chr(34) & ": " & Chr(34))
      strCBcompanyName = "|" & RemoveTLS(strCBcompanyName)
      strCBproductName = getdata(strCBresponseText, chr(34), "product_name" & Chr(34) & ": " & Chr(34))
      strCBproductName = "|" &RemoveTLS(strCBproductName)
      strCBprevalence = getdata(strCBresponseText, ",", "host_count" & Chr(34) & ": ")
      strCBhosts = getdata(strCBresponseText, ",", "hostname" & Chr(34) & ": ")
      strCBFileSize = getdata(strCBresponseText, ",", "orig_mod_len" & Chr(34) & ": ")
      strtmpCB_Fpath = getfilepath(strCBfilePath)
      RecordPathVendorStat strtmpCB_Fpath 'record path vendor statistics
    end if
  end if
end if
 
Set objHTTP = Nothing
end Function


Sub RecordPathVendorStat(strTmpR_Fpath) 'record path vendor statistics
if BoolRecordVendorPathStats = True then
  'normalize file path
  strTmpR_Fpath = Lcase(strTmpR_Fpath)
  strTmpR_Fpath = CleanFilePath(strTmpR_Fpath)
  if isnumeric(strCBprevalence) = False then strCBprevalence = 0 
  if DictPathVendorStat.exists(strTmpR_Fpath & "|" & strCBcompanyName) then 'update stats
    intPreviousPVScore = DictPathVendorStat.item(strTmpR_Fpath & "|" & strCBcompanyName)
	if isnumeric(intPreviousPVScore) = False then 
		intPreviousPVScore = 0
		logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "The following item did not exist in DictPathVendorStat " & strTmpR_Fpath & "|" & strCBcompanyName,False 
	end if
    if isnumeric(strCBprevalence) then
	  if strCBprevalence > 0 then
		DictPathVendorStat.item(strTmpR_Fpath & "|" & strCBcompanyName) = CLng(intPreviousPVScore) + CLng(strCBprevalence)
	  else
		DictPathVendorStat.item(strTmpR_Fpath & "|" & strCBcompanyName) = intPreviousPVScore + 1
	  end if
    else
      msgbox "strCBprevalence stat is not numeric:" & strCBprevalence
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "strCBprevalence stat is not numeric:" & strCBprevalence,False 
      DictPathVendorStat.item(strTmpR_Fpath & "|" & strCBcompanyName) = intPreviousPVScore + 1
    end if
  else 'add stats
    if isnumeric(strCBprevalence) then
      DictPathVendorStat.add strTmpR_Fpath & "|" & strCBcompanyName, CLng(strCBprevalence)
    else
      DictPathVendorStat.add strTmpR_Fpath & "|" & strCBcompanyName, 1
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "strCBprevalence stat is not numeric:" & strCBprevalence,False 
    end if
  end if
end if
end sub

Function CleanFilePath(strCFpath)
Dim strTmpCFpath: strTmpCFpath = strCFpath
  if instr(strTmpCFpath, "\\") then strTmpCFpath = replace(strTmpCFpath, "\\", "\")
  
if instr(strTmpCFpath, "c:\users\") then
  strTmpCFpath = replace(strTmpCFpath, "c:\users\", "")
  strTmpCFpath = "c:\users\[username]\" & Right(strTmpCFpath, len(strTmpCFpath) - instr(strTmpCFpath, "\"))
end if
  if right(strTmpCFpath, 1) = "\" then strTmpCFpath = left(strTmpCFpath, len(strTmpCFpath) -1)
  if right(strTmpCFpath, 1) = "\" then strTmpCFpath = left(strTmpCFpath, len(strTmpCFpath) -1)
CleanFilePath = strTmpCFpath
end Function

Function RemoveTLS(strTLS)
dim strTmpTLS
if len(strTLS) > 0 then
  for rmb = 1 to len(strTLS)
    if mid(strTLS, rmb, 1) <> " " then
      strTmpTLS = right(strTLS,len(strTLS) - RMB +1)
      exit for
    end if
  next
end if

if len(strTmpTLS) > 0 then
  for rmb = len(strTmpTLS)  to 1 step -1

    if mid(strTmpTLS, rmb, 1) <> " " then
      strTmpTLS = left(strTmpTLS,len(strTmpTLS) - (len(strTmpTLS) - RMB))
      exit for
    end if
  next
end if

RemoveTLS = strTmpTLS
end function

Function AddPipe(strpipeless)
dim strPipeAdded

if len(strpipeless) > 0 then
  if left(strpipeless, 1) <> "|" then 
    strPipeAdded = "|" & strpipeless

  else
    strPipeAdded = strpipeless
  end if  
else
  strPipeAdded = "|"
end if

AddPipe = strPipeAdded 
end function

Sub sbChangeColumnWidth(strCCLocation, intCCWidth)
If strCCLocation <> "" then
  objExcel.Worksheets(intTabCounter).Columns(strCCLocation).ColumnWidth = intCCWidth
end if
End Sub

Function ResolveVendorDetectionName(strAV_Vendor)
strTmpVendorDetectionName = getdata(strresponseText,", " & chr(34) & "update",strAV_Vendor & chr(34) & ": {" & chr(34) & "detected" & chr(34) & ": true, ")
ResolveVendorDetectionName = getdata(strTmpVendorDetectionName,chr(34),"result" & chr(34) & ": " & chr(34))
End Function 


sub CuckooHashSubmit(CuckoohashValue)
  strTmpCuckooAPIResponse = SubmitCuckooHash(CuckoohashValue)
  if instr(strTmpCuckooAPIResponse, "Rate limit exceeded for this API") > 0 then
    do while instr(strTmpCuckooAPIResponse, "Rate limit exceeded for this API") > 0
      wscript.sleep 10000
      strTmpCuckooAPIResponse = SubmitCuckooHash(CuckoohashValue)
    loop
  end if
  if instr(strTmpCuckooAPIResponse, "Sample not found in database") = 0 then _
  ProcessCuckoo strTmpCuckooAPIResponse
end sub            

Function SubmitCuckooHash(strTmpShash) 'search Cuckoo for hash results
Dim strTmpShshReturn
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Set search parameters", False
BoolPost = False
if len(strTmpShash) = 32 then 'Hash provided is MD5
    strTmpShshReturn = SearchCuckoo("/api/tasks/search/md5/", strTmpShash)

elseif len(strTmpShash) = 40 then 'Hash provided is SHA1
    strTmpShshReturn = SearchCuckoo("/api/tasks/search/sha1/", strTmpShash)
elseif len(strTmpShash) = 64 then 'Hash provided is SHA256
    strTmpShshReturn = SearchCuckoo("/api/tasks/search/sha256/", strTmpShash)        
elseif len(strTmpShash) = 128 then 'Hash provided is SHA512
    BoolPost = True
    strTmpShshReturn = SearchCuckoo("option=sha512&argument=" , strTmpShash)   
      
end if
SubmitCuckooHash = strTmpShshReturn
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End set search parameters", False
end Function

Function SubmitCuckooV2Hash(strTmpShash) 'search Cuckoo for hash results
Dim strTmpShshReturn
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Set search parameters", False
BoolPost = False
if len(strTmpShash) = 32 then 'Hash provided is MD5
    strTmpShshReturn = SearchCuckooV2("/files/view/md5/", strTmpShash)

elseif len(strTmpShash) = 40 then 'Hash provided is SHA1
    strTmpShshReturn = SearchCuckooV2("/files/view/sha1/", strTmpShash)
elseif len(strTmpShash) = 64 then 'Hash provided is SHA256
    strTmpShshReturn = SearchCuckooV2("/files/view/sha256/", strTmpShash)        
      
end if
SubmitCuckooV2Hash = strTmpShshReturn
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End set search parameters", False
end Function


Function SearchCuckooV2(strquery, strCdomain)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Start report search for " & strquery & strCdomain, False

if lcase(strCuckooV2IPAddress) = "cape.contextis.com" then
	exit Function 'unsupported 
elseif instr(lcase(strCuckooV2IPAddress),"http") then 
	 strAVEurl = strCuckooV2IPAddress & strCuckooPort
else
	 strAVEurl = "http://" & strCuckooV2IPAddress & strCuckooPort & strquery
end if
  strAVEurl = strAVEurl & strquery
'on error resume next
  objHTTP.open "GET", strAVEurl & strCdomain, False

  on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\Cu_Error.log", Date & " " & Time & " Cuckoo lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
  on error goto 0  

BoolPost = False 
  SearchCuckooV2 = objHTTP.responseText
Set objHTTP = Nothing
end Function

Function SearchCuckoo(strquery, strCdomain)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Start report search for " & strquery & strCdomain, False

if lcase(strCuckooIPAddress) = "cape.contextis.com" then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " CAPE lookup failed due to configuration. - cape.contexis.com does not support these API calls" ,False 
	exit Function 'unsupported 
elseif instr(lcase(strCuckooIPAddress),"http") then 
	 strAVEurl = strCuckooIPAddress
else
	 strAVEurl = "http://" & strCuckooIPAddress
end if

if BoolPost = true then

    strAVEurl = strAVEurl & strCAPEport & "/api/tasks/extendedsearch/"
    objHTTP.open "POST", strAVEurl, False
    objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
    objHTTP.setRequestHeader "Content-Length", len(strquery & strCdomain)

      if BoolDebugTrace = True then logdata strDebugPath & "\VT_HTTP_Debug" & "" & ".txt", "strFullAPIURL = " & strDataType & strScanDataInfo & strOptionalParameter, BoolEchoLog 
    on error resume next
    objHTTP.send strquery & strCdomain
else    
  strAVEurl = strAVEurl & strCAPEport & strquery

'on error resume next
  objHTTP.open "GET", strAVEurl & strCdomain, False

'  msgbox err.number & " " & err.message & vbcrlf & strAVEurl & strCdomain
'on error goto 0  

  on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\Cu_Error.log", Date & " " & Time & " Cuckoo lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
  on error goto 0  
end if
BoolPost = False 
  SearchCuckoo = objHTTP.responseText
Set objHTTP = Nothing

if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End report search", False
end Function


sub ParseCuckooV2(strViewResult)
strTmpFileSHA1 = GetData(strViewResult,chr(34), Chr(34))
strTmpFileSHA256 = GetData(strViewResult,chr(34), "sha256" & chr(34) & ": " & Chr(34))
strTmpFileSHA512 = GetData(strViewResult,chr(34), "sha512" & chr(34) & ": " & Chr(34))
strTmpFileMD5 = GetData(strViewResult,chr(34), "md5" & chr(34) & ": " & Chr(34))
strFileTypeLineE = GetData(strViewResult,chr(34), "file_type" & chr(34) & ": " & Chr(34))
strCBFileSize = GetData(strViewResult,",", "file_size" & chr(34) & ": ")
end sub

Sub ParseLooseIOC(strIOCreport)
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Starting IOC Parse", False
if instr(strIOCreport, "sha1" & chr(34) & ": ") = 0 then
    logdata strDebugPath & "\Cucoo_error.log", Date & " " & Time & " bad return from cuckoo: " & strIOCreport,False 
    objShellComplete.popup "bad return from cuckoo: " & strIOCreport
    exit sub
end if
arrayTmpSplit = split(strIOCreport, "sha1" & chr(34) & ": ")

strCuckooScore = GetData(arrayTmpSplit(1),",", "malscore" & chr(34) & ": ")
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Cuckoo score " & strCuckooScore, False
if StrDetectionTypeLineE = "" then StrDetectionTypeLineE = GetData(strIOCreport,chr(34), "malfamily" & chr(34) & ": " & Chr(34))


strTmpFileSHA1 = GetData(arrayTmpSplit(1),chr(34), Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - CstrTmpFileSHA1 " & strTmpFileSHA1, False
strTmpFileSHA256 = GetData(arrayTmpSplit(1),chr(34), "sha256" & chr(34) & ": " & Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strTmpFileSHA256 " & strTmpFileSHA256, False
strTmpFileSHA512 = GetData(arrayTmpSplit(1),chr(34), "sha512" & chr(34) & ": " & Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strTmpFileSHA512" & strTmpFileSHA512, False
strTmpFileMD5 = GetData(arrayTmpSplit(1),chr(34), "md5" & chr(34) & ": " & Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strTmpFileMD5 " & strTmpFileMD5, False
if strDetectNameLineE = "" then 
  if instr(arrayTmpSplit(1), "clamav" & chr(34) & ": " & Chr(34)) then 
    strDetectNameLineE = GetData(arrayTmpSplit(1),chr(34), "clamav" & chr(34) & ": " & Chr(34))
  end if
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strDetectNameLineE " & strDetectNameLineE, False
if strCBFileSize = "" or strCBFileSize = "|" then
  strCBFileSize = GetData(arrayTmpSplit(1),chr(10), "size" & chr(34) & ": ")
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strCBFileSize " & strCBFileSize, False
strFileTypeLineE = GetData(arrayTmpSplit(1),chr(34), "type" & chr(34) & ": " & Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strFileTypeLineE " & strFileTypeLineE, False
'strTmpFileImphash = GetData(arrayTmpSplit(1),chr(34), "pe_imphash" & chr(34) & ": " & Chr(34))
'strPE_TimeStamp = GetData(strIOCreport,chr(34), "pe_timestamp" & chr(34) & ": " & Chr(34))
if strCBdigSig = "" or strCBdigSig = "|" then
  strCBdigSig = GetData(arrayTmpSplit(0),chr(34), "cn" & chr(34) & ": " & Chr(34))
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - strCBdigSig " & strCBdigSig, False
strTmpFileYara = GetData(arrayTmpSplit(0),"]", chr(34) & "yara" & chr(34) & ": [")
'if BoolDebugTrace = True then logdata strDebugPath & "\VT_YARA" & "" & ".txt", Date & " " & Time & " - " & strTmpFileYara, False 'dumps a lot of data
ArrayYara = split(strTmpFileYara, "{")
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Starting YARA loop = " & ubound(ArrayYara), False
for each YARAentry in ArrayYARA
  strTmpYARA = getdata(YARAentry, chr(34), "description" & chr(34) & ": " & Chr(34))
  if strTmpYARA <> "" then
    if StrYARALineE = "" then 
      StrYARALineE = strTmpYARA
    else
      StrYARALineE = StrYARALineE & "^" & strTmpYARA
    end if
  end if
next
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End YARA loop", False

'strTmpIOC = getdata(strIOCreport, "static" & chr(34) & ":", "target" & chr(34) & ": {")  
'strTmpIOC = getdata(strIOCreport, "sha512" & chr(34) & ":", "sha1" & chr(34) & ": ")  

'StrTmpSandboxName = GetData(strIOCreport,chr(34), chr(34) & "name" & chr(34) & ": " & Chr(34))
 
'strTmpLegalCopyright = GetData(strIOCreport,"},", chr(34) & "LegalCopyright" & chr(34) & ",")
'strTmpLegalCopyright = GetData(strTmpLegalCopyright,Chr(34), chr(34) & "value" & chr(34) &  ": " & Chr(34))

'strTmpFileVersion = GetData(strIOCreport,"},", chr(34) & "LegalCopyright" & chr(34) & ",")
'strTmpFileVersion = GetData(strTmpFileVersion,Chr(34), chr(34))

strTmpCompanyName = GetData(strIOCreport,"],", chr(34) & "CompanyName" & chr(34) & ",")
strCBcompanyName = GetData(strTmpCompanyName,Chr(34), chr(34))
strCBcompanyName = nullPropertyStrings(strCBcompanyName)

strTmpProductName= GetData(strIOCreport,"],", chr(34) & "ProductName" & chr(34) & ",")
strCBproductName = GetData(strTmpProductName,Chr(34), chr(34))
strCBproductName = nullPropertyStrings(strCBproductName)

'strTmpProductVersion= GetData(strIOCreport,"},", chr(34) & "ProductVersion" & chr(34) & ",")
'strTmpProductVersion = GetData(strTmpProductVersion,Chr(34), chr(34) & "value" & chr(34) &  ": " & Chr(34))

'strTmpFileDescription= GetData(strIOCreport,"},", chr(34) & "FileDescription" & chr(34) & ",")
'strTmpFileDescription = GetData(strTmpFileDescription,Chr(34), chr(34) & "value" &  ": " & Chr(34))
'strTmpOriginalFilename= GetData(strIOCreport,"},", chr(34) & "Filename" & chr(34) & ",")
'strCBfilePath = GetData(strTmpOriginalFilename,Chr(34), chr(34) & "value" & chr(34) &  ": " & Chr(34))
'strTmpTranslation= GetData(strIOCreport,"},", chr(34) & "Translation" & chr(34) & ",")
'strTmpTranslation = GetData(strTmpTranslation,Chr(34), chr(34) & "value" & chr(34) &  ": " & Chr(34))
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End IOC Parse", False
end sub

Function nullPropertyStrings(StrPropertyValue)
select case StrPropertyValue
  Case "FileDescription"
  case "FileVersion"
  case "InternalName"
  Case "LegalCopyright"
  case "OriginalFilename"
  case "ProductName"
  case "ProductVersion"
  Case "AssemblyVersion"
  case else
    nullPropertyStrings = StrPropertyValue
end select
end function


Function ProcessCuckoo(strSearchResults) 'loop through each result from search and grab domains from IOC Detailed report
Dim BoolParseIOC
Dim strTmpCuckooID
Dim dictIPDomain: Set dictIPDomain = CreateObject("Scripting.Dictionary")
BoolParseIOC = True
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Start processing report", False
'msgbox instr(strSearchResults, CHr(34) & "data"  & chr(34) & ": [")

if instr(strSearchResults, CHr(34) & "id"  & chr(34) & ":") then 'basic search
'msgbox "basic strSearchResults=" & strSearchResults
  strIDs = split(strSearchResults, CHr(34) & "id"  & chr(34) & ":")
  for each strIDstring in strIDs 
    'msgbox strIDstring
    strTmpCuckooID = getdata(strIDstring, ","," ")
    'msgbox "strTmpCuckooID = " & strTmpCuckooID 
    if isnumeric(strTmpCuckooID) and len(strTmpCuckooID) > 0 then
      if strMyIDs = "" then
        strMyIDs = strTmpCuckooID & "|"
      else
        strMyIDs = strMyIDs & strTmpCuckooID & "|"
      end if
      'msgbox "strMyIDs= " & strMyIDs
      exit for 'Only get one result
    end if
  next
elseif instr(strSearchResults, CHr(34) & "data"  & chr(34) & ":") then 'extended search
'msgbox "extended strSearchResults=" & strSearchResults
  strIDs = getdata(strSearchResults, "]", CHr(34) & "data"  & chr(34) & ": [")
  'msgbox "strIDs=" & strIDs
  strIDs = split(strIDs, vblf)
  for each strIDstring in strIDs 
    if ReturnNumber(strIDstring) <> "" then
      if strMyIDs = "" then
        strMyIDs =  ReturnNumber(strIDstring) & "|"
      else
        strMyIDs = strMyIDs & ReturnNumber(strIDstring)  & "|"
      end if
      exit for 'Only get one result
    end if
  next
else
  
   objShellComplete.popup "error processing CAPE results: " & strSearchResults, 16
   logdata strDebugPath & "\CAPE_error.log", Date & " " & Time & " bad return from CAPE: " & strSearchResults,False 
  exit function
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - Report IDs: " & strMyIDs, False
strIDs = split(strMyIDs, "|")

for each strIDstring in strIDs 

  if strIDstring <> "" then
    'msgbox "filereport/" & strIDstring & "/json/"
    strTmpString = SearchCuckoo("/api/tasks/get/iocs/" & strIDstring & "/detailed/", "")
    if instr(strSearchResults, "Rate limit exceeded for this API") then
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - sleeping: 10150", False
		wscript.sleep 10150
        strTmpString = SearchCuckoo("/api/tasks/get/iocs/" & strIDstring & "/detailed/", "")
    end if
    if instr(strSearchResults, "Page not found at ") then
          objShellComplete.popup "error performing IOC lookup" & vbcrlf & "filereport/" & strIDstring & "/json/", 16
          LogData CurrentDirectory & "\IOC_match.txt", strTmpHash & "|error",False  
    end if
    strdomains = GetData(strSearchResults,"], ", "hosts" & chr(34) & ": [")
    if BoolParseIOC = True then
      ParseLooseIOC strTmpString
    end if
    arrayIPdomain = split(strdomains,"{")
    'msgbox "ubound\" & ubound(arrayIPdomain)
    for each strIPDpair in arrayIPdomain
      strIPaddress = getdata(strIPDpair, chr(34), "ip" & chr(34) & ": " & chr(34))
      strdomain = getdata(strIPDpair, chr(34), "hostname" & chr(34) & ": " & chr(34))
      'msgbox strdomain
      if strdomain <> "dns.msftncsi.com" and strdomain <> "watson.microsoft.com" and strdomain <> "shell.windows.com" then
        if dictIPDomain.exists(strdomain) = false then 
          dictIPDomain.add strdomain, strIPaddress
          if dictIDHash.exists(strdomain & "/" & strIPaddress) = false then 
            dictIDHash.add strdomain & "/" & strIPaddress, strTmpHash
          else
            dictIDHash.item(strdomain & "/" & strIPaddress) = dictIDHash.item(strdomain & "/" & strIPaddress) & ", " & strTmpHash
          end if
        end if
      end if
    next
  end if
  'wscript.sleep 20005
  Exit For
next
for each item in dictIPDomain
  stroutput = stroutput & Item & "/" & dictIPDomain.Item(Item) & vbcrlf
next
ProcessCuckoo = stroutput
dictIPDomain.removeall
if BoolDebugTrace = True then logdata strDebugPath & "\VT_cuckoo" & "" & ".txt", Date & " " & Time & " - End processing report", False
end Function


Function SQLTestConnect
Set Recordset = CreateObject("ADODB.Recordset")
boolConnectSuccess = True
on error resume next
oCNCT.Open oCS
if err.number <> 0 then 
  SQLTestConnect = False
  if BoolRunSilent = True or BoolDisableCacheLookup = True then 
	boolConnectSuccess = False
	exit function
  end if
  'SQLite database exists check
	msgbox err.message
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
    sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='VendorCache'"
    'sSQL = "select * from VirusTotal where MD5 = 'test1'"
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 

      wscript.echo "Table VendorCache does not exist. Attempting to create table"
      sSQL =  "CREATE TABLE VendorCache (MD5 TEXT,SHA1 TEXT,SHA256 TEXT,IMPHash TEXT,DateFirstSeen TEXT,VirusTotal TEXT,VTLastUpdate TEXT,ThreatCrowd TEXT,TCLastUpdate TEXT,ThreatGRID TEXT,TGLastUpdate TEXT,XForce TEXT,XFLastUpdate TEXT,MalShare TEXT,MSLastUpdate TEXT, ResourceID INTEGER)"
      oCNCT.Execute sSQL
      sSQL = "CREATE INDEX MD5 on VendorCache (MD5);"
      oCNCT.Execute sSQL
      sSQL = "CREATE INDEX SHA1 on VendorCache (SHA1);"
      oCNCT.Execute sSQL
      sSQL = "CREATE UNIQUE INDEX SHA256 on VendorCache (SHA256);"
      oCNCT.Execute sSQL
      sSQL = "CREATE INDEX IMPHash on VendorCache (IMPHash);"
      oCNCT.Execute sSQL
    else
      boolFoundBL = False
      Recordset.close
      sSQL = "PRAGMA table_info(VendorCache)"
      Recordset.Open sSQL,oCNCT
      Recordset.MoveFirst
      do while not Recordset.EOF
        strTmpColumnName = Recordset.fields.item("name")
        if strTmpColumnName = "ResourceID" then boolFoundBL = True
        Recordset.MoveNext
      loop
      if boolFoundBL = False then
        sSQL =  "ALTER TABLE VendorCache ADD COLUMN ResourceID INTEGER"
        oCNCT.Execute sSQL
      end if
    end if
    Recordset.close
    ' sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='NamedSources'"
    ' Recordset.Open sSQL,oCNCT
    ' If Recordset.EOF Then 
      ' wscript.echo "Table NamedSources does not exist. Attempting to create table"
      ' sSQL =  "CREATE TABLE NamedSources (NameID INTEGER PRIMARY KEY AUTOINCREMENT,SourceName TEXT)"
      ' oCNCT.Execute sSQL
    ' end if
    ' Recordset.close
    ' sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='ResourceInfo'"
    ' Recordset.Open sSQL,oCNCT
    ' If Recordset.EOF Then 

      ' wscript.echo "Table ResourceInfo does not exist. Attempting to create table"
      ' sSQL =  "CREATE TABLE ResourceInfo (ResourceID INTEGER PRIMARY KEY AUTOINCREMENT,ResourceShortDesc TEXT,ResourceDescription TEXT,Score INTEGER, NameID INTEGER)"
      ' oCNCT.Execute sSQL
    ' end if
     ' Recordset.close
     
    sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='PublisherDomains'"
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
      wscript.echo "Table PublisherDomains does not exist. Attempting to create table"
      sSQL =  "CREATE TABLE PublisherDomains (PublisherName TEXT,PubDomains TEXT)"
      oCNCT.Execute sSQL
      sSQL = "CREATE UNIQUE INDEX PublisherName on PublisherDomains (PublisherName);"
      oCNCT.Execute sSQL
    end if
    Recordset.close

    sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='DomainVend'"
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
      wscript.echo "Table DomainVend does not exist. Attempting to create table"
      'Threat Crowd - Only positive detections
      'Reverse DNS - Only if not NULL
      'Whois - Only if not NULL
      'VirusTotal - Only if positive detections
      'ET Intelligence - Only if positive detections
      'Country Name	Country Code	Region Name	Region Code	City Name	Creation Date	Reverse DNS	WHOIS

      sSQL =  "CREATE TABLE DomainVend (DomainName TEXT, CreatedDate TEXT, LastUpDate TEXT, VTdomain TEXT, TCdomain INTEGER, RevDomain TEXT, CountryNameDomain TEXT,	CountryCodeDomain TEXT, RegionNameDomain TEXT, RegionCodeDomain TEXT, CityNameDomain TEXT, CreationDate TEXT, WHOISName TEXT, IPaddress TEXT, ETdomain TEXT, Sinkhole TEXT)"
      oCNCT.Execute sSQL
      sSQL = "CREATE UNIQUE INDEX DomainName on DomainVend (DomainName);"
      oCNCT.Execute sSQL
      
      sSQL = "CREATE INDEX WHOISDName on DomainVend (WHOISName);"
      oCNCT.Execute sSQL
      sSQL = "CREATE INDEX dIPaddress on DomainVend (IPaddress);"
      oCNCT.Execute sSQL     
    end if
    Recordset.close
	sSQL = "PRAGMA table_info(DomainVend)"
	  Recordset.Open sSQL,oCNCT
	  Recordset.MoveFirst
	  boolFoundSH = False
	  do while not Recordset.EOF
		strTmpColumnName = Recordset.fields.item("name")
		if strTmpColumnName = "Sinkhole" then boolFoundSH = True
		Recordset.MoveNext
	  loop
	  if boolFoundSH = False then
		sSQL =  "ALTER TABLE DomainVend ADD COLUMN Sinkhole TEXT"
		oCNCT.Execute sSQL
	  end if
	  Recordset.close
	  sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='DB_IP'"
    
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
		enableIP_DB = False 'Disable use internal IP-DB for GeoIP
		If BoolWhoisDebug = True Then msgbox "missing IP_DB"
	end if
	Recordset.close
	
		  sSQL = "SELECT name FROM sqlite_master WHERE type='table' AND name='Tranco'"
    
    Recordset.Open sSQL,oCNCT
    If Recordset.EOF Then 
		boolTrancoSQL = False 'Disable use of internal Tranco list
		'If BoolDebugTrace = True Then msgbox "missing Tranco table"
	end if
	Recordset.close
	if boolTrancoSQL = True then 'Check index
		sSQL = "PRAGMA INDEX_LIST('Tranco');"
		Recordset.Open sSQL,oCNCT
		If Recordset.EOF Then 'create index
			sSQL = "CREATE INDEX TDomain on Tranco (T_Domain);"
			oCNCT.Execute sSQL
		end if
		Recordset.close
	end if

SQLTestConnect = boolConnectSuccess


end function



Function TableCheck
Dim boolMySQLsuccess: boolMySQLsuccess = True
Dim sSQL
sSQL = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'vttl' and table_name='VendorCache'"

on error resume next
Recordset.Open sSQL,oCNCT
if err.number <> 0 then 
  boolMySQLsuccess = False
  msgbox "Problem connecting to MySQL:" & vbcrlf & err.number & " " & err.description
end if
on error goto 0 
if boolMySQLsuccess = True then    
    If Recordset.EOF Then 

      wscript.echo "Table does not exist. Attempting to create table"
      sSQL =  "CREATE TABLE VendorCache (MD5 VARCHAR(64),SHA1 VARCHAR(64),SHA256 VARCHAR(64),IMPHash VARCHAR(64),DateFirstSeen TEXT,VirusTotal TEXT,VTLastUpdate TEXT,ThreatCrowd TEXT,TCLastUpdate TEXT,ThreatGRID TEXT,TGLastUpdate TEXT,XForce TEXT,XFLastUpdate TEXT,MalShare TEXT,MSLastUpdate TEXT, ResourceID INTEGER, INDEX(MD5), INDEX(SHA1), INDEX(SHA256), INDEX(IMPHash), INDEX(Resource(ID))"
      oCNCT_MySQL.Execute sSQL
    else
      'boolFoundBL = False
      'Recordset.close
      'sSQL = "desc VendorCache"
      'Recordset.Open sSQL,oCNCT_MySQL
      'Recordset.MoveFirst
      'do while not Recordset.EOF
      '  strTmpColumnName = Recordset.fields.item("field")
      '  if strTmpColumnName = "ResourceID" then boolFoundBL = True
      '  Recordset.MoveNext
      'loop
      'if boolFoundBL = False then
      '  sSQL =  "ALTER TABLE VendorCache ADD COLUMN ResourceID INTEGER"
      '  oCNCT_MySQL.Execute sSQL
      'end if
    end if
    Recordset.close
	'Not using these tables currently so commenting out.
    ' sSQL = "SELECT table_name FROM information_schema.tables WHERE table_schema = 	vttl' and table_name='NamedSources'"
    ' Recordset.Open sSQL,oCNCT_MySQL
    ' If Recordset.EOF Then 
      ' wscript.echo "Table does not exist. Attempting to create table"
      ' sSQL =  "CREATE TABLE NamedSources (NameID INTEGER PRIMARY KEY AUTO_INC'ENT,SourceName TEXT)"
      ' oCNCT_MySQL.Execute sSQL
    ' else
      ' msgbox "Table namedsources exists"
    ' end if
    ' Recordset.close
    ' sSQL = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'vttl' and table_name='ResourceInfo'"
    ' Recordset.Open sSQL,oCNCT_MySQL
    ' If Recordset.EOF Then 

      ' wscript.echo "Table does not exist. Attempting to create table"
      ' sSQL =  "CREATE TABLE ResourceInfo (ResourceID INTEGER PRIMARY KEY AUTO_INC'ENT,ResourceShortDesc TEXT,ResourceDescription TEXT,Score INTEGER, NameID INTEGER)"
      ' oCNCT_MySQL.Execute sSQL
    ' else
      ' msgbox "resourceinfo exists"
    ' end if
     ' Recordset.close

end if
TableCheck = boolMySQLsuccess

end Function



Sub LoadDSWhitelist
DictWhiteDSigNames.add "Microsoft Corporation", 2
DictWhiteDSigNames.add "Oracle America, Inc.", 2
DictWhiteDSigNames.add "Adobe Systems, Incorporated", 2
DictWhiteDSigNames.add "Google Inc", 2

end sub



Sub LoadRIPE_Dat
Dictripe.add "141", 1
Dictripe.add "145", 1
Dictripe.add "151", 1
Dictripe.add "188", 1
Dictripe.add "53", 1
Dictripe.add "2", 1
Dictripe.add "5", 1
Dictripe.add "31", 1
Dictripe.add "37", 1
Dictripe.add "46", 1
Dictripe.add "62", 1
Dictripe.add "77", 1
Dictripe.add "78", 1
Dictripe.add "79", 1
Dictripe.add "80", 1
Dictripe.add "81", 1
Dictripe.add "82", 1
Dictripe.add "83", 1
Dictripe.add "84", 1
Dictripe.add "85", 1
Dictripe.add "86", 1
Dictripe.add "87", 1
Dictripe.add "88", 1
Dictripe.add "89", 1
Dictripe.add "90", 1
Dictripe.add "91", 1
Dictripe.add "92", 1
Dictripe.add "93", 1
Dictripe.add "94", 1
Dictripe.add "95", 1
Dictripe.add "109", 1
Dictripe.add "176", 1
Dictripe.add "178", 1
Dictripe.add "185", 1
Dictripe.add "193", 1
Dictripe.add "194", 1
Dictripe.add "195", 1
Dictripe.add "212", 1
Dictripe.add "213", 1
Dictripe.add "217", 1
Dictripe.add "57", 1
Dictripe.add "51", 1
Dictripe.add "25", 1
end sub

sub LoadTLD
dictTLD.add ".ac",0
dictTLD.add ".ad",0
dictTLD.add ".ae",0
dictTLD.add ".af",0
dictTLD.add ".ag",0
dictTLD.add ".ai",0
dictTLD.add ".al",0
dictTLD.add ".am",0
dictTLD.add ".an",0
dictTLD.add ".ao",0
dictTLD.add ".aq",0
dictTLD.add ".ar",0
dictTLD.add ".as",0
dictTLD.add ".at",0
dictTLD.add ".au",0
dictTLD.add ".aw",0
dictTLD.add ".ax",0
dictTLD.add ".az",0
dictTLD.add ".ba",0
dictTLD.add ".bb",0
dictTLD.add ".bd",0
dictTLD.add ".be",0
dictTLD.add ".bf",0
dictTLD.add ".bg",0
dictTLD.add ".bh",0
dictTLD.add ".bi",0
dictTLD.add ".bj",0
dictTLD.add ".bl",0
dictTLD.add ".bm",0
dictTLD.add ".bn",0
dictTLD.add ".bo",0
dictTLD.add ".bq",0
dictTLD.add ".br",0
dictTLD.add ".bs",0
dictTLD.add ".bt",0
dictTLD.add ".bv",0
dictTLD.add ".bw",0
dictTLD.add ".by",0
dictTLD.add ".bz",0
dictTLD.add ".ca",0
dictTLD.add ".cc",0
dictTLD.add ".cd",0
dictTLD.add ".cf",0
dictTLD.add ".cg",0
dictTLD.add ".ch",0
dictTLD.add ".ci",0
dictTLD.add ".ck",0
dictTLD.add ".cl",0
dictTLD.add ".cm",0
dictTLD.add ".cn",0
dictTLD.add ".co",0
dictTLD.add ".cr",0
dictTLD.add ".cu",0
dictTLD.add ".cv",0
dictTLD.add ".cw",0
dictTLD.add ".cx",0
dictTLD.add ".cy",0
dictTLD.add ".cz",0
dictTLD.add ".de",0
dictTLD.add ".dj",0
dictTLD.add ".dk",0
dictTLD.add ".dm",0
dictTLD.add ".do",0
dictTLD.add ".dz",0
dictTLD.add ".ec",0
dictTLD.add ".ee",0
dictTLD.add ".eg",0
dictTLD.add ".eh",0
dictTLD.add ".er",0
dictTLD.add ".es",0
dictTLD.add ".et",0
dictTLD.add ".eu",0
dictTLD.add ".fi",0
dictTLD.add ".fj",0
dictTLD.add ".fk",0
dictTLD.add ".fm",0
dictTLD.add ".fo",0
dictTLD.add ".fr",0
dictTLD.add ".ga",0
dictTLD.add ".gb",0
dictTLD.add ".gd",0
dictTLD.add ".ge",0
dictTLD.add ".gf",0
dictTLD.add ".gg",0
dictTLD.add ".gh",0
dictTLD.add ".gi",0
dictTLD.add ".gl",0
dictTLD.add ".gm",0
dictTLD.add ".gn",0
dictTLD.add ".gp",0
dictTLD.add ".gq",0
dictTLD.add ".gr",0
dictTLD.add ".gs",0
dictTLD.add ".gt",0
dictTLD.add ".gu",0
dictTLD.add ".gw",0
dictTLD.add ".gy",0
dictTLD.add ".hk",0
dictTLD.add ".hm",0
dictTLD.add ".hn",0
dictTLD.add ".hr",0
dictTLD.add ".ht",0
dictTLD.add ".hu",0
dictTLD.add ".id",0
dictTLD.add ".ie",0
dictTLD.add ".il",0
dictTLD.add ".im",0
dictTLD.add ".in",0
dictTLD.add ".io",0
dictTLD.add ".iq",0
dictTLD.add ".ir",0
dictTLD.add ".is",0
dictTLD.add ".it",0
dictTLD.add ".je",0
dictTLD.add ".jm",0
dictTLD.add ".jo",0
dictTLD.add ".jp",0
dictTLD.add ".ke",0
dictTLD.add ".kg",0
dictTLD.add ".kh",0
dictTLD.add ".ki",0
dictTLD.add ".km",0
dictTLD.add ".kn",0
dictTLD.add ".kp",0
dictTLD.add ".kr",0
dictTLD.add ".kw",0
dictTLD.add ".ky",0
dictTLD.add ".kz",0
dictTLD.add ".la",0
dictTLD.add ".lb",0
dictTLD.add ".lc",0
dictTLD.add ".li",0
dictTLD.add ".lk",0
dictTLD.add ".lr",0
dictTLD.add ".ls",0
dictTLD.add ".lt",0
dictTLD.add ".lu",0
dictTLD.add ".lv",0
dictTLD.add ".ly",0
dictTLD.add ".ma",0
dictTLD.add ".mc",0
dictTLD.add ".md",0
dictTLD.add ".me",0
dictTLD.add ".mf",0
dictTLD.add ".mg",0
dictTLD.add ".mh",0
dictTLD.add ".mk",0
dictTLD.add ".ml",0
dictTLD.add ".mm",0
dictTLD.add ".mn",0
dictTLD.add ".mo",0
dictTLD.add ".mp",0
dictTLD.add ".mq",0
dictTLD.add ".mr",0
dictTLD.add ".ms",0
dictTLD.add ".mt",0
dictTLD.add ".mu",0
dictTLD.add ".mv",0
dictTLD.add ".mw",0
dictTLD.add ".mx",0
dictTLD.add ".my",0
dictTLD.add ".mz",0
dictTLD.add ".na",0
dictTLD.add ".nc",0
dictTLD.add ".ne",0
dictTLD.add ".nf",0
dictTLD.add ".ng",0
dictTLD.add ".ni",0
dictTLD.add ".nl",0
dictTLD.add ".no",0
dictTLD.add ".np",0
dictTLD.add ".nr",0
dictTLD.add ".nu",0
dictTLD.add ".nz",0
dictTLD.add ".om",0
dictTLD.add ".pa",0
dictTLD.add ".pe",0
dictTLD.add ".pf",0
dictTLD.add ".pg",0
dictTLD.add ".ph",0
dictTLD.add ".pk",0
dictTLD.add ".pl",0
dictTLD.add ".pm",0
dictTLD.add ".pn",0
dictTLD.add ".pr",0
dictTLD.add ".ps",0
dictTLD.add ".pt",0
dictTLD.add ".pw",0
dictTLD.add ".py",0
dictTLD.add ".qa",0
dictTLD.add ".re",0
dictTLD.add ".ro",0
dictTLD.add ".rs",0
dictTLD.add ".ru",0
dictTLD.add ".rw",0
dictTLD.add ".sa",0
dictTLD.add ".sb",0
dictTLD.add ".sc",0
dictTLD.add ".sd",0
dictTLD.add ".se",0
dictTLD.add ".sg",0
dictTLD.add ".sh",0
dictTLD.add ".si",0
dictTLD.add ".sj",0
dictTLD.add ".sk",0
dictTLD.add ".sl",0
dictTLD.add ".sm",0
dictTLD.add ".sn",0
dictTLD.add ".so",0
dictTLD.add ".sr",0
dictTLD.add ".ss",0
dictTLD.add ".st",0
dictTLD.add ".su",0
dictTLD.add ".sv",0
dictTLD.add ".sx",0
dictTLD.add ".sy",0
dictTLD.add ".sz",0
dictTLD.add ".tc",0
dictTLD.add ".td",0
dictTLD.add ".tf",0
dictTLD.add ".tg",0
dictTLD.add ".th",0
dictTLD.add ".tj",0
dictTLD.add ".tk",0
dictTLD.add ".tl",0
dictTLD.add ".tm",0
dictTLD.add ".tn",0
dictTLD.add ".to",0
dictTLD.add ".tp",0
dictTLD.add ".tr",0
dictTLD.add ".tt",0
dictTLD.add ".tv",0
dictTLD.add ".tw",0
dictTLD.add ".tz",0
dictTLD.add ".ua",0
dictTLD.add ".ug",0
dictTLD.add ".uk",0
dictTLD.add ".um",0
dictTLD.add ".us",0
dictTLD.add ".uy",0
dictTLD.add ".uz",0
dictTLD.add ".va",0
dictTLD.add ".vc",0
dictTLD.add ".ve",0
dictTLD.add ".vg",0
dictTLD.add ".vi",0
dictTLD.add ".vn",0
dictTLD.add ".vu",0
dictTLD.add ".wf",0
dictTLD.add ".ws",0
dictTLD.add ".ye",0
dictTLD.add ".yt",0
dictTLD.add ".za",0
dictTLD.add ".zm",0
dictTLD.add ".zw",0
end sub

Sub LoadARIN_Dat
DictArin.add "7", 1
DictArin.add "35", 1
DictArin.add "40", 1
DictArin.add "45", 1
DictArin.add "47", 1
DictArin.add "54", 1
DictArin.add "128", 1
DictArin.add "129", 1
DictArin.add "130", 1
DictArin.add "131", 1
DictArin.add "132", 1
DictArin.add "134", 1
DictArin.add "135", 1
DictArin.add "136", 1
DictArin.add "137", 1
DictArin.add "138", 1
DictArin.add "139", 1
DictArin.add "140", 1
DictArin.add "142", 1
DictArin.add "143", 1
DictArin.add "144", 1
DictArin.add "146", 1
DictArin.add "147", 1
DictArin.add "148", 1
DictArin.add "149", 1
DictArin.add "152", 1
DictArin.add "155", 1
DictArin.add "156", 1
DictArin.add "157", 1
DictArin.add "158", 1
DictArin.add "159", 1
DictArin.add "160", 1
DictArin.add "161", 1
DictArin.add "162", 1
DictArin.add "164", 1
DictArin.add "165", 1
DictArin.add "166", 1
DictArin.add "167", 1
DictArin.add "168", 1
DictArin.add "169", 1
DictArin.add "170", 1
DictArin.add "172", 1
DictArin.add "192", 1
DictArin.add "198", 1
DictArin.add "44", 1
DictArin.add "17", 1
DictArin.add "23", 1
DictArin.add "24", 1
DictArin.add "50", 1
DictArin.add "63", 1
DictArin.add "64", 1
DictArin.add "65", 1
DictArin.add "66", 1
DictArin.add "67", 1
DictArin.add "68", 1
DictArin.add "69", 1
DictArin.add "70", 1
DictArin.add "71", 1
DictArin.add "72", 1
DictArin.add "73", 1
DictArin.add "74", 1
DictArin.add "75", 1
DictArin.add "76", 1
DictArin.add "96", 1
DictArin.add "97", 1
DictArin.add "98", 1
DictArin.add "99", 1
DictArin.add "100", 1
DictArin.add "104", 1
DictArin.add "107", 1
DictArin.add "108", 1
DictArin.add "173", 1
DictArin.add "174", 1
DictArin.add "184", 1
DictArin.add "199", 1
DictArin.add "204", 1
DictArin.add "205", 1
DictArin.add "206", 1
DictArin.add "207", 1
DictArin.add "208", 1
DictArin.add "209", 1
DictArin.add "216", 1
DictArin.add "6", 1
DictArin.add "12", 1
DictArin.add "32", 1
DictArin.add "20", 1
DictArin.add "21", 1
DictArin.add "22", 1
DictArin.add "26", 1
DictArin.add "29", 1
DictArin.add "30", 1
DictArin.add "16", 1
DictArin.add "33", 1
DictArin.add "11", 1
DictArin.add "55", 1
DictArin.add "28", 1
DictArin.add "52", 1
DictArin.add "19", 1
DictArin.add "3", 1
DictArin.add "34", 1
DictArin.add "15", 1
DictArin.add "9", 1
DictArin.add "4", 1
DictArin.add "8", 1
DictArin.add "18", 1
DictArin.add "48", 1
DictArin.add "38", 1
DictArin.add "56", 1
DictArin.add "214", 1
DictArin.add "215", 1
DictArin.add "13", 1
End Sub


sub loadSigCheckData(strSigCheckFpath, boolUnicode)
if strSigCheckFpath = "" then
  wscript.echo "Please open the sigcheck csv"
  OpenFilePath1 = SelectFile( )
else
OpenFilePath1 = strSigCheckFpath
end if
if objFSO.fileexists(OpenFilePath1) then
  if boolUnicode = True then
    ANSIorUnicode = TristateTrue
  else
    ANSIorUnicode = TristateFalse
  end if
  Set objFile = objFSO.OpenTextFile(OpenFilePath1, ForReading, false, ANSIorUnicode)
  intCSVRowLocation = 0
  boolSuppressNoHash = False
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        intCSVRowLocation = intCSVRowLocation + 1
        strSCData = objFile.ReadLine 
        on Error GoTo 0
		'if boolSigCheckDebug = true then msgbox "CSV line length-" & len(strSCData)
        if BoolHeaderLocSet =True then
			if instrrev(strSCData, ",") + 1 = chr(34) then 'grab the rest of the row if it contains a quoted return character
			  do while right(strSCData,1) <> Chr(34) and Not objFile.AtEndOfStream
				if right(strSCData,1) <> Chr(34) then
				  strSCData = strSCData & objFile.ReadLine'  & objFile.ReadLine
				end if
			  loop
			end if
          
        end if
        if boolSigCheckDebug = true and BoolHeaderLocSet = False then msgbox "header row:" & strSCData
        ArraySigCheckData(intCSVRowLocation) = strSCData
        redim preserve ArraySigCheckData(intCSVRowLocation +1)
		if intCSVRowLocation > 6 and BoolHeaderLocSet = False and boolUnicode = False then 'failing to load data 
			redim ArraySigCheckData(1)
			loadSigCheckData strSigCheckFpath, true 'try reading as unicode
			exit sub
		end if
        if (BoolHeaderLocSet = False and (instr(strSCData, "Publisher") > 0 and instr(strSCData,	"Company") > 0 and instr(strSCData, "MD5") > 0)) or _
		(BoolHeaderLocSet = False and instr(strSCData, "File Name") > 0 and instr(strSCData,	"SHA256") > 0 and instr(strSCData, "# of Hosts") > 0) or _
		(InStr(strSCData,	"MD5") > 0 and instr(strSCData, "Path") > 0) or _
		(BoolHeaderLocSet = False and instr(strSCData, "Image Path") > 0 and instr(strSCData,	"MD5") > 0 and instr(strSCData, "Company") > 0) Then
          If instr(strSCData, "Image Path") > 0 and instr(strSCData,	"MD5") > 0 and instr(strSCData, "Entry Location") > 0 then 'autoruns
            boolSuppressNoHash = True
          end if
          'header row

          SetHeaderLocations strSCData
          BoolHeaderLocSet = True
		  'msgbox "header location set"
        elseIf BoolHeaderLocSet = True then
          if instr(strSCData, ",") then
            strSCMD5 = ReturnSigCheckItem(strSCData, intMD5Loc)
            if strSCMD5 <> "" then
              strSCMD5 = lcase(strSCMD5) 'needs to be lower case for comparison
              if dicMD5Loc.exists(strSCMD5) = false then
                dicMD5Loc.add strSCMD5, intCSVRowLocation
                if boolSigCheckDebug = true then msgbox "md5loc-" & intMD5Loc & "|" & intCSVRowLocation & "|" & strSCMD5
              end if
            else
              if boolSuppressNoHash = False then Msgbox "Could not process line in sigcheck: " & strSCData
            end if
          else
            Msgbox "no commas-" & strSCData
          end if
        end if
    end if
  loop
  objFile.close

else'file does not exist
  BoolSigCheckLookup = False
  BoolAddStats = False
end if
end sub


Function returnCellLocation(strQuotedLine, cellNumber) 'needed to support mixed quoted non-quoted csv
dim StrReturnCellL
  strTmpHArray = split(strQuotedLine, ",")
  redim tmpArrayPointer(ubound(strTmpHArray))
  boolQuoted = False
  intArrayCount = 0
  for cellCount = 0 to ubound(strTmpHArray)
	if boolQuoted = False then 
		tmpArrayPointer(intArrayCount) = cellCount
		'if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt",  "intArrayCount=" & intArrayCount & " cellCount=" & cellCount ,BoolEchoLog
		if cellNumber = intArrayCount then StrReturnCellL = cellCount
		intArrayCount = intArrayCount + 1 
	end if
	'msgbox "return cell:" & strTmpHArray(cellCount) & "|" & tmpArrayPointer(intArrayCount -1) & "|" & cellCount & "|" & boolQuoted
	if instr(strTmpHArray(cellCount),chr(34)) > 0 then 
		if boolQuoted = False and left(strTmpHArray(cellCount), 1) = chr(34) and right(strTmpHArray(cellCount),1) = chr(34) then
			boolQuoted = False
		elseif boolQuoted = True and right(strTmpHArray(cellCount), 1) = chr(34) then 
			boolQuoted = False
		elseif boolQuoted = False and left(strTmpHArray(cellCount), 1) = chr(34) then
			boolQuoted = True
		else
			'ignore quotes that aren't at the begening or end 
		end if
	end if
  next
returnCellLocation = StrReturnCellL  
end Function


Function ReturnSigCheckItem(StrRSCILine, intRSCILocation)
Dim StrRSCItem
Dim strSigCheckItem

intArrayPointer = returnCellLocation(StrRSCILine, intRSCILocation)
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt",  "intArrayPointer=" & intArrayPointer & itemCount & " intRSCILocation=" & intRSCILocation ,BoolEchoLog
if instr(StrRSCILine, chr(34) & ",") > 0 or instr(StrRSCILine, "," & Chr(34)) > 0 or (instr(StrRSCILine, vbtab) = 0 and instr(StrRSCILine, ",") > 0) then
	strTmpHArray = split(StrRSCILine, ",")
	if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt",  "ubound(strTmpHArray)=" & ubound(strTmpHArray),BoolEchoLog
	if ubound(tmpArrayPointer) >= intRSCILocation and cint(intRSCILocation) > -1 then
		if ubound(tmpArrayPointer) = intArrayPointer then
			strSigCheckItem = replace(strTmpHArray(intArrayPointer), Chr(34), "")
		elseif (tmpArrayPointer(intRSCILocation) +1 <> tmpArrayPointer(intRSCILocation +1)) then
			if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt",  tmpArrayPointer(intRSCILocation) +1 & "<>" &  tmpArrayPointer(intRSCILocation +1) ,BoolEchoLog
			strSigCheckItem = ""
			for itemCount = 0 to tmpArrayPointer(intRSCILocation +1) - (tmpArrayPointer(intRSCILocation) +1)
				strSigCheckItem = strSigCheckItem & replace(strTmpHArray(intArrayPointer + itemCount), Chr(34), "")
				'msgbox "strSigCheckItem" & strSigCheckItem
				if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt",  "arraylocation:" & intArrayPointer & itemCount & " strSigCheckItem:" & strSigCheckItem ,BoolEchoLog
			next
		else
			if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck.txt", "one cell item:" & strTmpHArray(intArrayPointer),BoolEchoLog
			strSigCheckItem = replace(strTmpHArray(intArrayPointer), Chr(34), "")
		end if
	
	else
		msgbox "sigcheck array mismatch:StrRSCILine=" & StrRSCILine & "&intArrayPointer=" & intArrayPointer  & "&ubound(tmpArrayPointer)=" & ubound(tmpArrayPointer)
		if cint(intArrayPointer) > -1 AND cint(intArrayPointer) <= ubound(strTmpHArray) then
			strSigCheckItem = replace(strTmpHArray(tmpArrayPointer(intArrayPointer)), Chr(34), "")
		end if
	end if
elseif  instr(StrRSCILine, vbtab) then
  strTmpHArray = split(StrRSCILine, vbtab)  
  'msgbox StrRSCILine
  'msgbox "ubound strTmpHArray " & ubound(strTmpHArray)
  if ubound(strTmpHArray) >= intRSCILocation then
    if inthfPathLoc = intRSCILocation then 'pull container from file path provided by EnCase
      StrRSCItem = right(strTmpHArray(intRSCILocation), len(strTmpHArray(intRSCILocation)) - instr(strTmpHArray(intRSCILocation), "\"))
      if instr(StrRSCItem, "\") =2 then 'make sure this is supposed to be a drive letter
        StrRSCItem = left(StrRSCItem, 1) & ":\" & right(StrRSCItem, len(StrRSCItem) - instr(StrRSCItem, "\"))
        StrRSCItem = lcase(StrRSCItem)
        strSigCheckItem = StrRSCItem
      else
        strSigCheckItem = strTmpHArray(intRSCILocation)
      end if
    else
      strSigCheckItem = strTmpHArray(intRSCILocation)
    end if
  end if
end if
ReturnSigCheckItem = strSigCheckItem
End Function


Sub SetHeaderLocations(StrHeaderText)
if instr(StrHeaderText, ",") or instr(StrHeaderText, vbtab) then
  if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "Header text:" & StrHeaderText ,BoolEchoLog
  if instr(StrHeaderText, ",") then 
    strTmpHArray = split(StrHeaderText, ",")
  else
    strTmpHArray = split(StrHeaderText, vbtab)
  end if
  for inthArrayLoc = 0 to ubound(strTmpHArray)
    strCellData = ReturnSigCheckItem(StrHeaderText, inthArrayLoc)
	'msgbox "debug4843:" & strCellData
  if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "Header item:" & strCellData ,BoolEchoLog
    select case strCellData
      case "Publisher"
        intPublisherLoc = inthArrayLoc
      case "Signer"
        intPublisherLoc = inthArrayLoc        
      case "Company"
        intCompanyLoc = inthArrayLoc
      Case "SHA1"
        intSHA1Loc = inthArrayLoc
      Case "IMP"
        intIMPLoc = inthArrayLoc
      Case "MD5"
        intMD5Loc = inthArrayLoc
        intRealMD5Loc = inthArrayLoc
      Case chr(34) & "MD5" & Chr(34)
        intMD5Loc = inthArrayLoc
        intRealMD5Loc = inthArrayLoc		
      Case "Path"
        inthfPathLoc = inthArrayLoc
      Case chr(34) & "Path" & Chr(34)
        inthfPathLoc = inthArrayLoc
	Case "Item Path"
        inthfPathLoc = inthArrayLoc
      Case "File Name"'crowdstrike process execution history
        inthfPathLoc = inthArrayLoc		
      Case "Product"
        inthfProductLoc = inthArrayLoc        
      Case "Logical Size"
        inthfSizeLoc = inthArrayLoc 
      Case "CB Prevalence"
        inthfPrevalenceLoc = cint(inthArrayLoc)
	  Case "# of Hosts"'crowdstrike process execution history
		inthfPrevalenceLoc = cint(inthArrayLoc)
    'Network AMP CSV
      Case "SHA256"
        if boolNetAMPCSV = True then
          intMD5Loc = inthArrayLoc
          intSHA256Loc = inthArrayLoc
          boolSHA256csvLookup = True
        end if
      Case "Size (KB)"
        inthfSizeLoc = inthArrayLoc 
      Case "File Name"
        inthfPathLoc = inthArrayLoc        
      case "Image Path"
        inthfPathLoc = inthArrayLoc
      Case "Date Time Added" 'Rhythm Cb Response Scripts
      	dateTimeLoc = inthArrayLoc
    end Select
    
    select case replace(strTmpHArray(inthArrayLoc),chr(34),"")
      case "File Path"
        int_CBFP_Location = inthArrayLoc
      case "CB File Path"
        int_CBFP_Location = inthArrayLoc        
      case "Digital Sig"
        intCBDS_Location = inthArrayLoc   
      case "CB Digital Sig"
        intCBDS_Location = inthArrayLoc                
      case "CB Company Name"
        intCBCN_Location = inthArrayLoc
      case "Company Name"
        intCBCN_Location = inthArrayLoc
      Case "MD5"
        intMD5Loc = inthArrayLoc
      Case "Host Name"
        if boolOutputHosts = True then intHostLocation = inthArrayLoc
    end select
  next
  if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "Header Locations:" &  "md5|" & "inthfPathLoc|" & "intPublisherLoc|" &  "inthfProductLoc|" &  "intCompanyLoc|" & "inthfPrevalenceLoc|inthfSizeLoc"   ,BoolEchoLog
  if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "Header Locations:" & intMD5Loc & "|" & inthfPathLoc & "|" & intPublisherLoc & "|" & inthfProductLoc & "|" & intCompanyLoc & "|" & inthfPrevalenceLoc & "|" &  inthfSizeLoc  ,BoolEchoLog
else
  Msgbox "error parsing header"
end if
end sub


sub SigCheckSSoutput(strSCSSO_hash)
Dim IntSCArrayLoc
strSCSSO_hash = lcase(strSCSSO_hash)
IntSCArrayLoc = dicMD5Loc.item(strSCSSO_hash)
if boolSigCheckDebug = true then msgbox "sigcheck hash:" & strSCSSO_hash
if boolSigCheckDebug = true then msgbox "sigcheck hash data:" & ArraySigCheckData(IntSCArrayLoc)
if boolSigCheckDebug = true then msgbox "BoolSigCheckLookup=" & BoolSigCheckLookup
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", ArraySigCheckData(IntSCArrayLoc),BoolEchoLog
if IntSCArrayLoc <> "" then
  if BoolSigCheckLookup = True or BoolEnCaseLookup = True then
    strCBfilePath = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),inthfPathLoc)
  end if
  if BoolSigCheckLookup = True then
    if intPublisherLoc > -1 then strCBdigSig = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intPublisherLoc)
    if inthfProductLoc > -1 then strCBproductName = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),inthfProductLoc)
    if intCompanyLoc > -1 then strCBcompanyName = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intCompanyLoc)
    If dateTimeLoc > -1 Then 
    	tmpDFS = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),dateTimeLoc) 'load date first seen from import file
		SetDateFirstSeen tmpDFS
	End If	
    if intRealMD5Loc <> "" then strFileMD5 = lcase(ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intRealMD5Loc))
    if intSHA256Loc <> "" then strFileSHA256 = lcase(ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intSHA256Loc))
    if intSHA1Loc <> "" then strFileSHA1 = lcase(ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intSHA1Loc))
    if intIMPLoc <> "" then strFileIMP = lcase(ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intIMPLoc))

  end if
  if cint(inthfPrevalenceLoc) > -1 then 'CB custom CSV export
    strCBprevalence = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),inthfPrevalenceLoc)
    if inthfSizeLoc > -1 then strCBFileSize = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),inthfSizeLoc)
  else
    strCBprevalence = 1
  end if
  if cint(intHostLocation) > 0 Then
    strCBhosts = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),intHostLocation)
  end if
  if BoolEnCaseLookup = True then
    strCBFileSize  = ReturnSigCheckItem(ArraySigCheckData(IntSCArrayLoc),inthfSizeLoc)
    if left(strCBFileSize,1) = Chr(34) then strCBFileSize = right(strCBFileSize, len(strCBFileSize)-1)
    if right(strCBFileSize,1) = Chr(34) then strCBFileSize = left(strCBFileSize, len(strCBFileSize)-1)    
  end if  
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "IntSCArrayLoc=" & IntSCArrayLoc ,BoolEchoLog
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "Locations:" & inthfPathLoc & "|" & intPublisherLoc & "|" & inthfProductLoc & "|" & intCompanyLoc & "|" & inthfPrevalenceLoc & "|" &  inthfSizeLoc  ,BoolEchoLog
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", strCBfilePath & "|" & strCBdigSig & "|" & strCBproductName & "|" & strCBcompanyName & "|" & strCBprevalence & "|" & strCBFileSize ,BoolEchoLog
else
  if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "hash lookup failed " & strSCSSO_hash ,BoolEchoLog
end if

strtmpCB_Fpath = getfilepath(strCBfilePath)
if instr(strtmpCB_Fpath, "\") then 
	RecordPathVendorStat strtmpCB_Fpath 'record path vendor statistics
end if
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
    ' Source:   http://social.technet.microsoft.com/Forums/scriptcenter/en-US/a3b358e8-15&ælig;-4ba3-bca5-ec349df65ef6

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


sub loadEncaseData
wscript.echo "Please open the EnCase or NetAMP export"
OpenFilePath1 = SelectFile( )
if BoolDebugTrace = True then logdata strDebugPath & "\sigcheck" & "" & ".txt", "File path:" & OpenFilePath1 ,BoolEchoLog
if objFSO.fileexists(OpenFilePath1) then
  Set objFile = objFSO.OpenTextFile(OpenFilePath1)
  intCSVRowLocation = 0
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        intCSVRowLocation = intCSVRowLocation + 1
        strSCData = objFile.ReadLine 
        on Error GoTo 0
        if boolReplaceCommaTab =True then
          strSCData = replace(strSCData, ",", vbtab)
        end if
        ArraySigCheckData(intCSVRowLocation) = strSCData 'load CSV line into cache
        redim preserve ArraySigCheckData(intCSVRowLocation +1)
        if BoolHeaderLocSet = False and instr(strSCData, "Item Path") > 0 and instr(strSCData,	"Logical Size") > 0 and instr(strSCData, "MD5") > 0  or _
         BoolHeaderLocSet = False and instr(strSCData, "File Name") > 0 and instr(strSCData,	"SHA256") > 0 and instr(strSCData, "Size (KB)") > 0  then
          'header row
          SetHeaderLocations strSCData
          BoolHeaderLocSet = True
          if instr(strSCData,	"SHA256") > 0 then 'NetAMP
            boolReplaceCommaTab = True
            boolNetAMPCSV = True
          else
            boolReplaceCommaTab = False
          end if
        elseIf BoolHeaderLocSet = True then
          if instr(strSCData, vbtab) then
            strTmpHArray = split(strSCData, vbtab)  
            strSCMD5 = lcase(replace(strTmpHArray(intMD5Loc), vbtab, ""))
            if dicMD5Loc.exists(strTmpHArray(intMD5Loc)) = false then
              dicMD5Loc.add strTmpHArray(intMD5Loc), intCSVRowLocation
              if boolSigCheckDebug = True then msgbox "md5loc-" & strTmpHArray(intMD5Loc) & "|" & intCSVRowLocation
            end if
          else
            Msgbox "no commas-" & strSCData
          end if
        end if
    end if
  loop
  objFile.close
else'file does not exist
  BoolEnCaseLookup = True
  BoolAddStats = False
end if
if BoolHeaderLocSet = False then 
  intAnswer = msgbox("EnCase export did not successfully import. Make sure the export is ANSI not unicode. Do you want to continue?",vbYesNo, "VTTL Question")
  if intAnswer = vbNo then wscript.quit(148)
end if
end sub



Sub AddStatsCSV()
DIm BoolASCHeaderLocSet: BoolASCHeaderLocSet = False
Dim strASCSigPrev
Dim strASCVendPathPrev
if objFSO.fileexists(strSSfilePath) then
  Set objFile = objFSO.OpenTextFile(strSSfilePath)
  intCSVRowLocation = 0
  Do While Not objFile.AtEndOfStream
    strASCSigPrev = ""
    strASCVendPathPrev = ""
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        intCSVRowLocation = intCSVRowLocation + 1
        strSCData = objFile.ReadLine 
        on Error GoTo 0
        if BoolASCHeaderLocSet =True then
          do while right(strSCData,1) <> Chr(34) and Not objFile.AtEndOfStream
            if right(strSCData,1) <> Chr(34) then
              strSCData = strSCData & objFile.ReadLine  & objFile.ReadLine
            end if
          loop
        end if 'File Path	Digital Sig

        if BoolASCHeaderLocSet = False and instr(strSCData, "File Path") > 0 and instr(strSCData,	"Digital Sig") > 0 and instr(strSCData, "Hash") > 0 then
          'header row
          SetHeaderLocations strSCData
          BoolASCHeaderLocSet = True
          'msgbox "header-" & strSCData
          logdata  strStatsOutput, strSCData & "," & Chr(34) & "Dig Sig Prev" & Chr(34) & "," & Chr(34) & "Path Vendor Prev" & Chr(34), false
        elseIf BoolASCHeaderLocSet = True then
          if instr(strSCData, chr(34) & "," & Chr(34)) then
            strTmpHArray = split(strSCData, chr(34) & "," & Chr(34))  
            strTmpFilePath = replace(strTmpHArray(int_CBFP_Location), Chr(34), "")
            strTmpDigSig = replace(strTmpHArray(intCBDS_Location), Chr(34), "")
            strTmpFCompName = replace(strTmpHArray(intCBCN_Location), Chr(34), "")
            'msgbox strTmpFilePath & "|" & strTmpDigSig & "|" & strTmpFCompName
            strTmpCB_Fpath = lcase(getfilepath(strTmpFilePath))
            strTmpCB_Fpath = CleanFilePath(strTmpCB_Fpath)
            if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log", "line values:" & strTmpFilePath & "|" & strTmpDigSig & "|" & strTmpFCompName, false
            if strTmpDigSig <> "" and DictDSigNames.exists(strTmpDigSig) then
              if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log", "dictsigname:" & strTmpDigSig & "|" & DictDSigNames.item(strTmpDigSig) & "|" & intCBDSP_location, false
              strASCSigPrev = DictDSigNames.item(strTmpDigSig)
            end if
            if DictPathVendorStat.exists(strTmpCB_Fpath & "|" & strTmpFCompName) then
              if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log",  "vendor stat: " & DictPathVendorStat.item(strTmpCB_Fpath & "|" & strTmpFCompName) & "|" & intCBPVP_Location, false
              strASCVendPathPrev = DictPathVendorStat.item(strTmpCB_Fpath & "|" & strTmpFCompName)
            elseif strTmpCB_Fpath <> "" then
              'msgbox "problem processing entry: " & strTmpCB_Fpath & "|" & strTmpFCompName
              if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log","problem processing entry: " & strTmpCB_Fpath & "|" & strTmpFCompName, false
            end if
            logdata  strStatsOutput, strSCData & "," & Chr(34) & strASCSigPrev & Chr(34)& "," & Chr(34) & strASCVendPathPrev & Chr(34), false
          else
            Msgbox "no commas-" & strSCData
          end if
        end if
    end if
  loop
  objFile.close 
end if
end sub

		
Sub AddStatsExcel()
intWriteRowCounter = 1
mycolumncounter = 1
Do Until objExcel.Cells(1,mycolumncounter).Value = ""
  if objExcel.Cells(1,mycolumncounter).Value = "CB File Path" then int_CBFP_Location = mycolumncounter '
  if objExcel.Cells(1,mycolumncounter).Value = "CB Digital Sig" then intCBDS_Location = mycolumncounter '
  if objExcel.Cells(1,mycolumncounter).Value = "CB Company Name" then intCBCN_Location = mycolumncounter '
  if objExcel.Cells(1,mycolumncounter).Value = "File Path" then int_CBFP_Location = mycolumncounter '
  if objExcel.Cells(1,mycolumncounter).Value = "Digital Sig" then intCBDS_Location = mycolumncounter '
  if objExcel.Cells(1,mycolumncounter).Value = "Company Name" then intCBCN_Location = mycolumncounter '
  
  
  mycolumncounter = mycolumncounter +1
loop
if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log", "Excel header locations:" & int_CBFP_Location & "|" & intCBDS_Location & "|" & intCBCN_Location, false
Write_Spreadsheet_Cell "Dig Sig Prev", mycolumncounter
intCBDSP_location = mycolumncounter
mycolumncounter = mycolumncounter +1
Write_Spreadsheet_Cell "Path Vendor Prev", mycolumncounter
intCBPVP_Location = mycolumncounter


Do Until objExcel.Cells(intWriteRowCounter,1).Value = ""
  strTmpFilePath =  objExcel.Cells(intWriteRowCounter,int_CBFP_Location).Value
  strTmpDigSig =  objExcel.Cells(intWriteRowCounter,intCBDS_Location).Value
  strTmpFCompName =  objExcel.Cells(intWriteRowCounter,intCBCN_Location).Value
  'msgbox strTmpFilePath & "|" & strTmpDigSig & "|" & strTmpFCompName
  strTmpCB_Fpath = lcase(getfilepath(strTmpFilePath))
  strTmpCB_Fpath = CleanFilePath(strTmpCB_Fpath)
  if strTmpDigSig <> "" and DictDSigNames.exists(strTmpDigSig) then
    if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log", "dictsigname:" & strTmpDigSig & "|" & DictDSigNames.item(strTmpDigSig) & "|" & intCBDSP_location, false
    Write_Spreadsheet_Cell DictDSigNames.item(strTmpDigSig), intCBDSP_location
  end if
  if DictPathVendorStat.exists(strTmpCB_Fpath & "|" & strTmpFCompName) then
    if booldebugtrace = True then logdata strDebugPath & "\AddSettings.log",  "vendor stat: " & DictPathVendorStat.item(strTmpCB_Fpath & "|" & strTmpFCompName) & "|" & intCBPVP_Location, false
    Write_Spreadsheet_Cell DictPathVendorStat.item(strTmpCB_Fpath & "|" & strTmpFCompName), intCBPVP_Location
  elseif strTmpCB_Fpath <> "" then
    msgbox "problem processing entry: " & strTmpCB_Fpath & "|" & strTmpFCompName
  end if
  intWriteRowCounter = intWriteRowCounter +1
loop

end sub
Sub Write_Spreadsheet_Cell(strSScell, intColumnWrite)
    objExcel.Cells(intWriteRowCounter, intColumnWrite).Value = strSScell
    wscript.sleep 10
'intWriteRowCounter = intWriteRowCounter + 1
end sub

Sub AddQueueParameter(strTmpParameter)
if strQueueParameters = "" then
  strQueueParameters = strTmpParameter
else
  strQueueParameters = strQueueParameters & " " & strTmpParameter
end if
end sub

sub PPointSubmit(strPPdataType)
'Proofpoint ET Intelligence lookups
if BoolUseETIntelligence = True then
  strTmpETI = CheckProofPoint(strPPdataType, strData)

  if strTmpETI <> "" then
    if strPPoint_Output = "" then
      strPPoint_Output = strData & " - ET Intelligence: " & strTmpETI
    else
      strPPoint_Output = strPPoint_Output & vbcrlf & strData & " - ET Intelligence: " & strTmpETI
    end if

    if strPPdataType = "md5" then strTmpETI = "X"
    strTmpPPointLine = "|" & strTmpETI
  end if
end If
etHashLookedUp = True
end sub


Function CheckProofPoint(StrPP_dataType, strPP_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
dim strAssocWith
select case(StrPP_dataType)
  case "domain"
    strAVEurl = "https://api.emergingthreats.net/v1/domains/" & strPP_ScanItem & "/reputation"
    sSQL = "select ETdomain from DomainVend where DomainName = ? " 
    StrTmpETdata = ReturnSQLiteItem(sSQL, strPP_ScanItem, "ETdomain")
    if StrTmpETdata <> "" and isnull(StrTmpETdata) = False then
      CheckProofPoint = StrTmpETdata
      exit function
    end if
  case "ip"
    strAVEurl = "https://api.emergingthreats.net/v1/ips/" & strPP_ScanItem & "/reputation"
  case "md5"
    strAVEurl = "https://api.emergingthreats.net/v1/samples/" & strPP_ScanItem
end select
  objHTTP.open "GET", strAVEurl, False
  objHTTP.setRequestHeader "Authorization", strETIntelligenceAPIKey
  

on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Proofpoint lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
on error goto 0  

if BoolDebugTrace = True then logdata strDebugPath & "\VT_PP" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 

if len(objHTTP.responseText) > 0 then
  if instr(objHTTP.responseText, "success" & chr(34) & ":true") then
    if StrPP_dataType = "domain" then strAssocWith = "domain name"
    if StrPP_dataType = "ip" then strAssocWith = "IP address"
    if StrPP_dataType = "md5" then strAssocWith = "hash"
    if instr(objHTTP.responseText, "md5sum" & chr(34) & ":") then'hash
      CheckProofPoint = "Proofpoint has information on the hash "
    elseif instr(objHTTP.responseText, "category" & chr(34) & ":") then'domain or IP
      'CheckProofPoint = "Proofpoint has samples associated with " & strAssocWith & " - " & strAVEurl & strPP_ScanItem
      arrayPPcategories = split(objHTTP.responseText, "category" & chr(34) & ":")
      for each strCategory in arrayPPcategories
        if instr(strCategory, "score") then
          strPPcategoryName = Getdata(strCategory, chr(34), chr(34))
          strPPcategoryScore = Getdata(strCategory, "}", "score" & chr(34) & ":")
          if strppAllCategories = "" then
            strppAllCategories = strPPcategoryName & "=" & strPPcategoryScore
          else
            strppAllCategories = strppAllCategories & "^" & strPPcategoryName & "=" & strPPcategoryScore
          end if
        end if
      next
      CheckProofPoint = strppAllCategories
    elseif instr(objHTTP.responseText, "MD5,") then 'successful lookup will no results
      CheckProofPoint = "Proofpoint doesn't have information associated with " & strAssocWith & " - " & strAVEurl & strPP_ScanItem
    end if
  elseif instr(objHTTP.responseText, ":" & chr(34) & ":No malware sample found" & chr(34) & "," ) then
    'don't error log. This is expected.
  else
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Proofpoint lookup failed with HTTP error. - " & objHTTP.responseText,False 
  end if
end if

'MsgBox objHTTP.responseText
Set objHTTP = Nothing
end Function


Function CheckProofpIDS(StrPP_dataType, strPP_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnURL
dim strAssocWith
select case(StrPP_dataType)
  case "domain"
    strAVEurl = "https://api.emergingthreats.net/v1/domains/" & strPP_ScanItem & "/events"
    sSQL = "select ETdomain from DomainVend where DomainName = ? " 
    StrTmpETdata = ReturnSQLiteItem(sSQL, strPP_ScanItem, "ETdomain")
    if StrTmpETdata <> "" and isnull(StrTmpETdata) = False then
      CheckProofPoint = StrTmpETdata
      exit function
    end if
  case "ip"
    strAVEurl = "https://api.emergingthreats.net/v1/ips/" & strPP_ScanItem & "/events"
  case "md5"
    strAVEurl = "https://api.emergingthreats.net/v1/samples/" & strPP_ScanItem  & "/events"
end select
  objHTTP.open "GET", strAVEurl, False
  objHTTP.setRequestHeader "Authorization", strETIntelligenceAPIKey
  

on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Proofpoint lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
on error goto 0  

if BoolDebugTrace = True then logdata strDebugPath & "\VT_PP" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 

if len(objHTTP.responseText) > 0 then
  if instr(objHTTP.responseText, "success" & chr(34) & ":true") then
    if instr(objHTTP.responseText, "{") then'domain or IP
      'CheckProofPoint = "Proofpoint has samples associated with " & strAssocWith & " - " & strAVEurl & strPP_ScanItem
      arrayPPcategories = split(objHTTP.responseText, "{")
      for each strCategory in arrayPPcategories
        if instr(strCategory, "signature") then
          strPPcategoryScore = Getdata(strCategory, chr(34), "signature" & chr(34) & ":" & chr(34))
          strppAllCategories = concatenateItem(strppAllCategories, strPPcategoryScore, "^")
        end if
      next
      CheckProofpIDS = strppAllCategories
    end if
  elseif instr(objHTTP.responseText, ":" & chr(34) & ":No malware sample found" & chr(34) & "," ) then
    'don't error log. This is expected.
  else
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " Proofpoint IDS lookup failed with HTTP error. - " & objHTTP.responseText,False 
  end if
end if

'MsgBox objHTTP.responseText
Set objHTTP = Nothing
end Function


Function Base64Encode(inData)
  'rfc1521
  '2001 Antonin Foller, Motobit Software, http://Motobit.cz
  Const Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  Dim cOut, sOut, I
  
  'For each group of 3 bytes
  For I = 1 To Len(inData) Step 3
    Dim nGroup, pOut, sGroup
    
    'Create one long from this 3 bytes.
    nGroup = &H10000 * Asc(Mid(inData, I, 1)) + _
      &H100 * MyASC(Mid(inData, I + 1, 1)) + MyASC(Mid(inData, I + 2, 1))
    
    'Oct splits the long To 8 groups with 3 bits
    nGroup = Oct(nGroup)
    
    'Add leading zeros
    nGroup = String(8 - Len(nGroup), "0") & nGroup
    
    'Convert To base64
    pOut = Mid(Base64, CLng("&o" & Mid(nGroup, 1, 2)) + 1, 1) + _
      Mid(Base64, CLng("&o" & Mid(nGroup, 3, 2)) + 1, 1) + _
      Mid(Base64, CLng("&o" & Mid(nGroup, 5, 2)) + 1, 1) + _
      Mid(Base64, CLng("&o" & Mid(nGroup, 7, 2)) + 1, 1)
    
    'Add the part To OutPut string
    sOut = sOut + pOut
    
    'Add a new line For Each 76 chars In dest (76*3/4 = 57)
    'If (I + 2) Mod 57 = 0 Then sOut = sOut + vbCrLf
  Next
  Select Case Len(inData) Mod 3
    Case 1: '8 bit final
      sOut = Left(sOut, Len(sOut) - 2) + "=="
    Case 2: '16 bit final
      sOut = Left(sOut, Len(sOut) - 1) + "="
  End Select
  Base64Encode = sOut
End Function


Function MyASC(OneChar)
  If OneChar = "" Then MyASC = 0 Else MyASC = Asc(OneChar)
End Function


Function CheckPassiveTotal(StrPP_dataType, strPT_ScanItem)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
Dim strAVEurl
Dim strReturnData
dim strAssocWith
Dim boolSuccessfulLookup: boolSuccessfulLookup = False
if StrPP_dataType = "whois" then
  if BoolUseSQLite = True then 
    strReturnData = PubDomainLookup(strPT_ScanItem)
    if strReturnData <> "" then
      strPassiveTotal = strReturnData
      exit function
    end if
  else
    if DictOrgWhois.exists(strPT_ScanItem) = True then 
      strPassiveTotal = DictOrgWhois.item(strPT_ScanItem)
      exit function
    end if
  end if
end if
if intPTlookupCount < intPTDailyLimit then 

  select case(StrPP_dataType)
    case "domain"
      strAVEurl = "https://api.passivetotal.org/v2/enrichment?:query=" & strPT_ScanItem
    case "ip"
      strAVEurl = "https://api.passivetotal.org/v2/enrichment?:query=" & strPT_ScanItem
    case "whois"
      strAVEurl = "https://api.passivetotal.org/v2/whois/search?query=" & strPT_ScanItem & "&field=organization"
    case "cert"
      strAVEurl = "https://api.passivetotal.org/v2/ssl-certificate/search?query=" & strPT_ScanItem & "&field=subjectOrganizationName"
  end select

    
    'objHTTP.setRequestHeader 
    objHTTP.open "GET", strAVEurl, False,strPTAPIuser, strPTAPIkey
    objHTTP.setRequestHeader "Authorization", "Basic " & Base64Encode(strPTAPIuser & ":" & strPTAPIkey)
    

  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " PassiveTotal lookup failed with HTTP error. - " & err.description,False 
      exit function 
    end if
  on error goto 0  

  if BoolDebugTrace = True then logdata strDebugPath & "\VT_PP" & "" & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 

  if len(objHTTP.responseText) > 0 then
    if instr(objHTTP.responseText, "results" & chr(34) & ":") then
      if instr(objHTTP.responseText, chr(34) & "dynamicDns" & chr(34) & ":") then'domain
        CheckPassiveTotal = "PassiveTotal has information on the hash " & " - " & strAVEurl & strPT_ScanItem
      elseif instr(objHTTP.responseText, "'sinkhole':") then'IP
      
      elseif instr(objHTTP.responseText, chr(34) & "domain" & chr(34) & ":") then'Whois
        'msgbox getdata(objHTTP.responseText, chr(34), chr(34) & "domain" & chr(34) & ": " & chr(34))
        strPassiveTotal = grabDomains(objHTTP.responseText)
        boolSuccessfulLookup = True

      elseif instr(objHTTP.responseText, chr(34) & "subjectCommonName" & chr(34) & ":") then
        strPassiveTotal = getdata (objHTTP.responseText, chr(34), chr(34) & "subjectCommonName" & chr(34) & ": " & chr(34))
        boolSuccessfulLookup = True
      end if
    elseIf instr(objHTTP.responseText, "Quota has been exceeded!" & chr(34) & ",") then
      logdata CurrentDirectory & "\VTTL_Error.log",  Date & " " & Time & " PassiveTotal quota hit! Disabling PassiveTotal lookup for 24 hours.", False
      intPTlookupCount = intPTDailyLimit
    ElseIf instr(objHTTP.responseText, "API key provided does not match any user." & chr(34) & ",") then
        BoolUsePassiveTotal = False
        logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " PassiveTotal authentication error. Disabling PassiveTotal - " & objHTTP.responseText,False 
    else
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " PassiveTotal lookup failed with HTTP error. - " & objHTTP.responseText,False 
    end if
  end if

  if boolSuccessfulLookup = True then
    if strPassiveTotal <> "" then
      logdata strCachePath & "\orgwho.dat", strPT_ScanItem & "|" & strPassiveTotal,false
      if DictOrgWhois.exists(strPT_ScanItem) = False then _
                 DictOrgWhois.add strPT_ScanItem, strPassiveTotal
      if BoolUseSQLite = True then pubdomainsave strPT_ScanItem, strPassiveTotal
      CheckPassiveTotal = "PassiveTotal whois lookup successful "  & " - " & strPT_ScanItem & "=" & strPassiveTotal
    else
      CheckPassiveTotal = "PassiveTotal whois lookup successful but did not have results"  & " - " & strPT_ScanItem
    end if
 
  end if
  'MsgBox objHTTP.responseText
 
  Set objHTTP = Nothing
  intPTlookupCount = intPTlookupCount +1
elseif intPTlookupCount = intPTDailyLimit then
  strPTdateTrack = now
  intPTlookupCount = intPTlookupCount +1
else
  if datediff("n", strPTdateTrack,now) > 1440 then intPTlookupCount = 0
end if
end Function


Function grabDomains(strPTdata)
Dim strReturnDomains
if instr(strPTdata, chr(34) & "contactEmail" &  chr(34) & ": ") then
arrayPTsplit = split(strPTdata, chr(34) & "contactEmail" &  chr(34) & ": ") 
intDomainCount = 0
for each strPTsection in arrayPTsplit
if instr(strPTsection, chr(34) & "domain" & chr(34) & ":") then'Whois
      if strReturnDomains = "" then
        strReturnDomains = getdata(strPTsection, chr(34), chr(34) & "domain" & chr(34) & ": " & chr(34))
        intDomainCount = intDomainCount +1
      else
        strReturnDomains = strReturnDomains & "^" & getdata(strPTsection, chr(34), chr(34) & "domain" & chr(34) & ": " & chr(34))
        intDomainCount = intDomainCount +1
      end if
      if intDomainCount > 2 then exit for
end if
next
end if
grabDomains = strReturnDomains
end function


Function CreateFolder(strFolderPath)
if objFSO.folderexists(strFolderPath) = False then _
objFSO.createfolder(strFolderPath)
CreateFolder = strFolderPath
end Function


Function PubDomainLookup(strPublisher)
Dim strTmpPubDomains

sSQL = "select PubDomains from PublisherDomains where PublisherName = ? " 
strTmpPubDomains = ReturnSQLiteItem(sSQL, strPublisher, "PubDomains")
 

    Set Recordset = CreateObject("ADODB.Recordset")
if strTmpPubDomains = "" then 'query internal whois database
  Set Recordset = CreateObject("ADODB.Recordset")
  Set cmd = Nothing
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
  sSQL = "select DomainName from DomainVend where WHOISName = ? " 
   set objparameter0 = cmd.createparameter("@domainName", 129, 1, len(strPublisher),strPublisher)

         cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
          Recordset.Open cmd

  If not Recordset.EOF Then 
    do while not Recordset.EOF
      if strTmpPubDomains = "" then

        strTmpPubDomains = Recordset.fields.item("DomainName")
      else
        strTmpPubDomains = strTmpPubDomains & "^" & Recordset.fields.item("DomainName")
      end if
      Recordset.movenext
    loop
  end if
    Set cmd = Nothing
    Set objparameter0 = Nothing
end if
PubDomainLookup = strTmpPubDomains
end function


Sub PubDomainSave(strPublisher, strTmpPubDomains)
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
sSQL = "INSERT INTO PublisherDomains(PublisherName, PubDomains) VALUES(?, ?)"

  set objparameter0 = cmd.createparameter("@Publisher", 129, 1, len(strPublisher),strPublisher)
  set objparameter1 = cmd.createparameter("@PubDomains", 129, 1, len(strTmpPubDomains),strTmpPubDomains)

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


Function GetWebCategoryfromVT(strVTreturned)
Dim strReturnVal
if instr(strVTreturned, chr(34) & "categories" & Chr(34) & ": [") then 
  strReturnVal = GetData(strVTreturned, "]", chr(34) & "categories" & Chr(34) & ": [")
elseif instr(strVTreturned, "category" & Chr(34) & ": " & Chr(34)) then 
    strReturnVal = GetData(strVTreturned, Chr(34) ,"category" & Chr(34) & ": " & Chr(34))
end if
if instr(strReturnVal, ", ") then
  strReturnVal = replace(strReturnVal, ", ", "^")
end if
if instr(strReturnVal, chr(34)) then  strReturnVal = replace(strReturnVal, chr(34), "")

GetWebCategoryfromVT = strReturnVal
end function


Function CheckWhoAPI(strWHOISURL, strDomainName)
if datediff("s", strWAPIdateTrack,now) > intWhoAPILimit then 
  StrValidDomainName = RemoveInvalidFromDomain(strDomainName)
  Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")

  strAVEurl = strWHOISURL & "apikey=" & strWAPIkey & "&r=whois&domain=" & StrValidDomainName
   
  'objHTTP.setRequestHeader 
  objHTTP.open "GET", strAVEurl
   
  on error resume next
   objHTTP.send 
   if err.number <> 0 then
     logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " WhoAPI lookup failed with HTTP error. - " & err.description,False 
     exit function 
   end if
  on error goto 0  


  if BoolDebugTrace = True then logdata strdomainreportsPath & "\VT_Wapi_domains_" & strData & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  if len(objHTTP.responseText) > 0 then
	
    if (instr(objHTTP.responseText, "status" & chr(34) & ":" & Chr(34) & "0" & Chr(34)) or instr(objHTTP.responseText, "status" & chr(34) & ":" & Chr(34) & "7" & Chr(34))) and _
     instr(objHTTP.responseText, "registered" & Chr(34) & ":true") > 0 then
      if boolwhoisdebug = True then msgbox "WhoAPI response"
      ' set city, region, and country code for spreadsheet output
      if strTmpCITlineE = "" or strTmpCITlineE = "|" then
      strTmpCITlineE = Getdata(objHTTP.responseText, Chr(34), "city" & Chr(34) & ":" & Chr(34))
      strTmpCITlineE = "|" & CleanupWhoisData(strTmpCITlineE)
      end if
      if strTmpRNlineE = "" or strTmpRNlineE = "|" then
      strTmpRNlineE = Getdata(objHTTP.responseText , Chr(34), "state" & Chr(34) & ":" & Chr(34))
      strTmpRNlineE = "|" & CleanupWhoisData(strTmpRNlineE)
      end if
      if strTmpCClineE = "" or strTmpCClineE = "|" then
      strTmpCClineE = Getdata(objHTTP.responseText , Chr(34), "country" & Chr(34) & ":" & Chr(34))
      strTmpCClineE = "|" & CleanupWhoisData(strTmpCClineE)
      end if

      if strTmpWCO_CClineE = "" or strTmpWCO_CClineE = "|" then
		  strTmpWCO_CClineE = Getdata(objHTTP.responseText, Chr(34), "date_created" & Chr(34) & ":" & Chr(34))
		  strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
	  end if
	  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after WhoAPI but before moveSS: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE , false

      MoveSSLocationEntries 'check if country code is listed as country name

	  'loop through organization entries checking for value
      if instr(objHTTP.responseText, "organization" & Chr(34) & ":") > 0 then
        arrayOrg = split(objHTTP.responseText, "organization" & Chr(34) & ":")
        for intOrg  = 1 to ubound(arrayOrg)
          strWhoIsIP_return = Getdata(arrayOrg(intOrg), Chr(34),Chr(34))
          if strWhoIsIP_return <> "" then exit for
        next
      end if
      
      if CheckBadValues(strWhoIsIP_return) then _
       strWhoIsIP_return = Getdata(objHTTP.responseText , Chr(34), "name" & Chr(34) & ":" & Chr(34))
      
      if CheckBadValues(strWhoIsIP_return) = True then 
        logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " WhoAPI parsing error. - " & objHTTP.responseText,False 
 
        strWhoIsIP_return = WhoIsDomain_Parse(objHTTP.responseText)
      elseif strTmpWCO_CClineE = "|" then
        WhoIsDomain_Parse objHTTP.responseText
      else
        if boolwhoisdebug = True then msgbox "WhoAPI success: " & strWhoIsIP_return
      end if
      CheckWhoAPI = strWhoIsIP_return
    elseIf instr(objHTTP.responseText, chr(34) & "Query high usage limit exceeded." & chr(34)) or _
    instr(objHTTP.responseText, chr(34) & "No more than " & chr(34)) and instr(objHTTP.responseText, chr(34) & "request per minute is allowed." & chr(34)) then
      objShellComplete.popup "quota hit! Are you running multiple WhoAPI queries?", 14
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " WhoAPI lookup quota limit hit",False 
      if boolwhoisdebug = True then msgbox "WhoAPI lookup quota limit hit"
    elseIf instr(objHTTP.responseText, chr(34) & "status" & chr(34) & ":12,") then
      msgbox "Invalid API key " & strWAPIkey
    elseIf instr(objHTTP.responseText, "Registrant Name:") > 0 then
      if boolwhoisdebug = True then msgbox "WhoAPI parsing failed. Sending to VT parser."
      CheckWhoAPI = WhoIsDomain_Parse(objHTTP.responseText)
    elseif instr(objHTTP.responseText, "created:     ") > 0 then
      strTmpWCO_CClineE = Getdata(objHTTP.responseText,"#", "created:     ")
        strTmpWCO_CClineE = left(strTmpWCO_CClineE, len(instr(strTmpWCO_CClineE, "e") -1))
      strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
      strWhoIsIP_return = Getdata(objHTTP.responseText , "r", "owner:      ")
    else
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " WhoAPI lookup on " & StrValidDomainName & " failed with HTTP error. - " & objHTTP.responseText,False 
    end if
    'check for sinkhole domain
    CheckWhoISData objHTTP.responseText
  end if

  'MsgBox objHTTP.responseText
   
  Set objHTTP = Nothing
  strWAPIdateTrack = Now
end if
end Function


Function WhoisCacheLookup(strWhoisDomain)
if booluseSQLite = true then
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
  Set Recordset = CreateObject("ADODB.Recordset")
  'sSQL =  "CREATE TABLE DomainVend (DomainName TEXT, CreatedDate TEXT, LastUpDate TEXT, VTdomain TEXT, TCdomain INTEGER, RevDomain TEXT, CountryNameDomain TEXT,	CountryCodeDomain TEXT, RegionNameDomain TEXT, RegionCodeDomain TEXT, CityNameDomain TEXT, CreationDate TEXT, WHOISName TEXT, IPaddress TEXT, ETdomain TEXT, Sinkhole TEXT)"
  sSQL = "Select CountryNameDomain, CountryCodeDomain, RegionNameDomain, RegionCodeDomain, CityNameDomain, CreationDate, WHOISName, LastUpDate FROM DomainVend WHERE DomainName = ?"
  set objparameter = cmd.createparameter("@DomainName", 129, 1, len(strWhoisDomain),strWhoisDomain)
  cmd.Parameters.Append objparameter
  cmd.CommandText = sSQL
  Recordset.Open cmd

  If not Recordset.EOF Then 
      strTmpCNlineE = "|" & Recordset.fields.item("CountryNameDomain")
      strTmpCClineE = "|" & Recordset.fields.item("CountryCodeDomain")
      strTmpRNlineE = "|" & Recordset.fields.item("RegionNameDomain")
      strTmpRClineE = "|" & Recordset.fields.item("RegionCodeDomain")
      strTmpCITlineE = "|" & Recordset.fields.item("CityNameDomain")
      strTmpWCO_CClineE = Recordset.fields.item("CreationDate")
	  strTmpCacheLineE = Recordset.fields.item("LastUpDate")
      strTmpWCO_CClineE = "|" & EpochConvert(strTmpWCO_CClineE)
	  strTmpCacheLineE = "|" & EpochConvert(strTmpCacheLineE)

      WhoisCacheLookup = Recordset.fields.item("WHOISName")

  end if
  set objparameter = Nothing
  Set cmd = Nothing
else
  if DictWhois.exists(strWhoisDomain) = True then 
    strTmpWdata = DictWhois.item(strWhoisDomain)
    if BoolWhoisDebug = True then msgbox "Cached lookup return:" & strTmpWdata
    if instr(strTmpWdata, "^") then
      arrayWdata = split(strTmpWdata, "^")
      WhoisCacheLookup = right(arrayWdata(0), len(arrayWdata(0)) - instr(arrayWdata(0), "|"))
      strTmpCNlineE = "|" & arrayWdata(1)
      strTmpCClineE = "|" & arrayWdata(2)
      strTmpRNlineE = "|" & arrayWdata(3)
      strTmpRClineE = "|" & arrayWdata(4)
      strTmpCITlineE = "|" & arrayWdata(5)
      strTmpWCO_CClineE = "|" & arrayWdata(6)
    end if
  end if
end if
end Function


Function EpochConvert(intEpochTime)

      if isnumeric(intEpochTime) then 
        intdcreated = clng(intEpochTime)
        EpochConvert = DateAdd("s", intdcreated, "01/01/1970 00:00:00")
      else
		EpochConvert = intEpochTime
	  end if
end function


Function GetFormattedDate(strDateUF)
  'http://learningpcs.blogspot.com/2011/03/vbscript-format-date-as-yyyy-mm-dd.html
  strDayUF = DatePart("d", strDateUF)
  strMonthUF = DatePart("m", strDateUF)
  strYearUF = DatePart("yyyy", strDateUF)
  If strDayUF < 10 Then
    strDayUF = "0" & strDayUF
  End If
  If strMonthUF < 10 Then
    strMonthUF = "0" & strMonthUF
  End If
  GetFormattedDate = strYearUF & "-" & strMonthUF & "-" & strDayUF
End Function


Function CacheWhois(strWhoisDomain, strWhoIsName)
if isnull(strWhoIsName) then  exit function

StrNow = DateDiff("s", "01/01/1970 00:00:00", Now())
if strTmpWCO_CClineE <> "|" and strTmpWCO_CClineE <> "" then
  strDateCreated = replace(strTmpWCO_CClineE,"|", "")
  'msgbox "strDateCreated before changes:" & strDateCreated
  strDateCreated =  ReformatDateTime(strDateCreated, "Whois")
  if mid(strDateCreated, 11,1) = "T" then
    strDateCreated = replace(strDateCreated,"T", " ")
  end if
  if mid(strDateCreated, 20,1) = "-" then
    if instr(right(strDateCreated, 3), ":") > 0 then
      strTimeOffset = left(right(strDateCreated, 5), 2) * 60 '-360
      strTimeOffset = strTimeOffset + right(strDateCreated, 2) '-360 + 00
      strTimeOffset = left(right(strDateCreated, 6), 1) & strTimeOffset '-360
      strDateCreated = ConvertToUTC(left(strDateCreated, 19),strTimeOffset)
    else
      strDateCreated = ConvertToUTC(left(strDateCreated, 19),right(strDateCreated, len(strDateCreated) -19))
    end if
  end if
  if isnumeric(strDateCreated) then 
    intdcreated = clng(strDateCreated)
    strDateCreated = DateAdd("s", intdcreated, "01/01/1970 00:00:00")
    
  end if
  if right(strDateCreated, 4) = " UTC" then 
    strDateCreated = left(strDateCreated, len(strDateCreated) -4)
    
  end if
  if mid(strDateCreated, 5,1) = "." and mid(strDateCreated, 8,1) = "." then
    strDateCreated = replace(strDateCreated, ".", "/")
  end if

  if instr(strDateCreated, ", ") > 2 then
	'remove weekday: Wed, 15 Jan 2014 00:00:00 GMT (AlienVault)
	strDateCreated = right(strDateCreated, len(strDateCreated) - instr(strDateCreated, ", ") -1) 

	

  end if
	if right(strDateCreated, 4)  = " GMT" then
		strDateCreated = left(strDateCreated, len(strDateCreated) - 4)
		'msgbox strDateCreated
	end if
	
	if mid(strDateCreated, len(strDateCreated) -2,1)  = "+" then '"2016-06-22 12:34:05+03"
		strDateCreated = left(strDateCreated, len(strDateCreated) - 3)
	end if
	
  'format spreadsheet output date consistently 
  if isdate(strDateCreated) then
	strTmpCreationD = GetFormattedDate(strDateCreated) & " " & FormatDateTime(strDateCreated,4)
	strTmpWCO_CClineE = "|" & strTmpCreationD	
  end if
  
  on error resume next
  strDateCreated = DateDiff("s", "01/01/1970 00:00:00", strDateCreated)
  if err.number <> 0 then 
    objShellComplete.popup "date conversion issue: " &  strDateCreated & vbcrlf & strTmpWCO_CClineE, 20
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & "Whois date conversion issue: " &  strDateCreated & "|" & strTmpWCO_CClineE ,False 
  on error goto 0

  end if
else
  strDateCreated = ""
end if
if BoolUseSQLite = True then 
  set objparameter0 = Nothing
  set objparameter1 = Nothing
  set objparameter2 = Nothing
  set objparameter3 = Nothing
  set objparameter4 = Nothing
  set objparameter5 = Nothing
  set objparameter6 = Nothing
  set objparameter7 = Nothing
  set objparameter8 = Nothing

  strCNlineE = Replace(strTmpCNlineE, "|", "")
  strCClineE  = Replace(strTmpCClineE, "|", "")
  strRNlineE  = Replace(strTmpRNlineE, "|", "")
   strRClineE  = Replace(strTmpRClineE, "|", "")
   strCITlineE = Replace(strTmpCITlineE, "|", "")
 

  Set cmd = createobject("ADODB.Command")
  set objparameter0 = cmd.createparameter("@created", 129, 1, len(StrNow),StrNow)
  set objparameter1 = cmd.createparameter("@lastupdate", 129, 1, len(StrNow),StrNow)
  if len(strCNlineE) > 0 then set objparameter2 = cmd.createparameter("@strTmpCNlineE", 129, 1, len(strCNlineE),strCNlineE)
  if len(strCClineE) > 0 then set objparameter3 = cmd.createparameter("@strTmpCClineE", 129, 1, len(strCClineE),strCClineE)
  if len(strRNlineE) > 0 then set objparameter4 = cmd.createparameter("@strTmpRNlineE", 129, 1, len(strRNlineE),strRNlineE)
  if len(strRClineE) > 0 then set objparameter5 = cmd.createparameter("@strTmpRClineE", 129, 1, len(strRClineE),strRClineE)
  if len(strCITlineE) > 0 then set objparameter6 = cmd.createparameter("@strTmpCITlineE", 129, 1, len(strCITlineE),strCITlineE)
  if len(strDateCreated) > 0 then set objparameter7 = cmd.createparameter("@strTmpWCO_CClineE", 129, 1, len(strDateCreated),strDateCreated)
  'on error resume next
  if len(strWhoIsName) > 0 then set objparameter8 = cmd.createparameter("@strWhoIsName", 129, 1, len(strWhoIsName),strWhoIsName)
  if err.number <> 0 then msgbox err.number & " " & err.description & vbcrlf & "whoisname=" & strWhoIsName & vbcrlf & "whoisname len=" & len(strWhoIsName)
  'on error goto 0
  'UpdateDomainVendTable strWhoisDomain, objCreatedDate, objLastUpDate, objVTdomain, objTCdomain, objRevDomain, objCountryNameDomain,	CountryCodeDomain, objRegionNameDomain, objRegionCodeDomain, objCityNameDomain, objCreationDate,  objWHOISName, objIPaddress, objETdomain)
  UpdateDomainVendTable strWhoisDomain, objparameter0, objparameter1,     ""       , ""          , ""          ,      objparameter2,	    objparameter3,       objparameter4,       objparameter5,       objparameter6, objparameter7,  objparameter8, "", "", "", ""
  Set cmd = Nothing
  set objparameter0 = Nothing
  set objparameter1 = Nothing
  set objparameter2 = Nothing
  set objparameter3 = Nothing
  set objparameter4 = Nothing
  set objparameter5 = Nothing
  set objparameter6 = Nothing
  set objparameter7 = Nothing
  set objparameter8 = Nothing

else
  if DictWhois.exists(strWhoisDomain) = False then 

    strTmpWdata= strWhoIsName  & "^" & strTmpCNlineE & "^" & strTmpCClineE & "^" & strTmpRNlineE & "^" & strTmpRClineE & "^" & strTmpCITlineE & "^" & strTmpWCO_CClineE 
    strTmpWdata = replace(strTmpWdata, "|", "")
    logdata strCachePath & "\whois.dat",   strWhoisDomain & "|" & strTmpWdata, false
  end if    
      
end if
end Function


Function AppendValues(strAggregate,strAppend)
    if strAggregate = "" then
      strAggregate = strAppend
    else
      strAggregate = strAggregate & ", " & strAppend
    end if
AppendValues = strAggregate
end Function


Sub UpdateDomainVendTable(strdomainName, objCreatedDate, objLastUpDate, objVTdomain, objTCdomain, objRevDomain, objCountryNameDomain,	CountryCodeDomain, objRegionNameDomain, objRegionCodeDomain, objCityNameDomain, objCreationDate, objWHOISName, objIPaddress, objETdomain, ObjXForce, ObjSinkhole)
'sSQL =  "CREATE TABLE DomainVend (DomainName TEXT, CreatedDate TEXT, LastUpDate TEXT, VTdomain TEXT, TCdomain INTEGER, RevDomain TEXT, CountryNameDomain TEXT,	CountryCodeDomain TEXT, RegionNameDomain TEXT, RegionCodeDomain TEXT, CityNameDomain TEXT, CreationDate TEXT, ReverseDNS TEXT, WHOISName TEXT, IPaddress TEXT, ETdomain TEXT, Sinkhole TEXT)"
Set Recordset = CreateObject("ADODB.Recordset")
Set cmd = createobject("ADODB.Command")
cmd.ActiveConnection = oCNCT
sSQL = "SELECT LastUpDate FROM DomainVend WHERE DomainName = ?"
cmd.CommandText = sSQL
set objparameter = cmd.createparameter("@DomainName", 129, 1, len(strdomainName),strdomainName)
cmd.Parameters.Append objparameter
Recordset.Open cmd
If Recordset.EOF Then
  sSQL = "INSERT INTO DomainVend("
  
else
  sSQL = "UPDATE DomainVend SET "
end if
Recordset.close
Set cmd = nothing
Set cmd = createobject("ADODB.Command")
cmd.ActiveConnection = oCNCT  
if sSQL = "INSERT INTO DomainVend(" then 
  set objparameter = cmd.createparameter("@DomainName", 129, 1, len(strdomainName),strdomainName)
  cmd.Parameters.Append objparameter
  strInsertStatement = "DomainName"
  strInsertValue = "?"

  'date created should only be set on creation
  if isobject(objCreatedDate) then 
    if Not objCreatedDate is Nothing then  
      cmd.Parameters.Append objCreatedDate
      strInsertStatement = AppendValues(strInsertStatement, "CreatedDate")
      strInsertValue = AppendValues(strInsertValue, "?")
      strUpdateValue = "CreatedDate = ?"
      if BoolDebugDomainSQL = True then msgbox "adding objCreatedDate"
    end if
  end if
end if


if isobject(objLastUpDate) then 
  if Not objLastUpDate is Nothing then 
    cmd.Parameters.Append objLastUpDate
    strInsertStatement = AppendValues(strInsertStatement, "LastUpDate")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "LastUpDate = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objLastUpDate " & cmd.Parameters.item(cmd.Parameters.count -1)
	if BoolDebugDomainSQL = True then msgbox "strUpdateValue=" & strUpdateValue
  end if
end if
if isobject(objVTdomain) then 
  if Not objVTdomain is Nothing then 
    cmd.Parameters.Append objVTdomain
    strInsertStatement = AppendValues(strInsertStatement, "VTdomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "VTdomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objVTdomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if  
if isobject(objTCdomain) then 
  if Not objTCdomain is Nothing then 
    cmd.Parameters.Append objTCdomain
    strInsertStatement = AppendValues(strInsertStatement, "TCdomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "TCdomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objTCdomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if  
if isobject(objRevDomain) then 
  if Not objRevDomain is Nothing then 
    cmd.Parameters.Append objRevDomain
    'msgbox cmd.Parameters.count
    'msgbox cmd.Parameters.item(cmd.Parameters.count -1)
    strInsertStatement = AppendValues(strInsertStatement, "RevDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "RevDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objRevDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(objCountryNameDomain) then 
  if Not objCountryNameDomain is Nothing then 
    cmd.Parameters.Append objCountryNameDomain
    strInsertStatement = AppendValues(strInsertStatement, "CountryNameDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "CountryNameDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objCountryNameDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(CountryCodeDomain) then 
  if Not CountryCodeDomain is Nothing then 
    on error resume next
    cmd.Parameters.Append CountryCodeDomain
    if err.number <>0 then msgbox err.number & " " & err.description & vbcrlf & "CountryCodeDomain.value=" & CountryCodeDomain.value
    on error goto 0
    strInsertStatement = AppendValues(strInsertStatement, "CountryCodeDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "CountryCodeDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding CountryCodeDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if

if isobject(objRegionNameDomain) then 
  if Not objRegionNameDomain is Nothing then 
    cmd.Parameters.Append objRegionNameDomain
    strInsertStatement = AppendValues(strInsertStatement, "RegionNameDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "RegionNameDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objRegionNameDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(objRegionCodeDomain) then 
  if Not objRegionCodeDomain is Nothing then 
    cmd.Parameters.Append objRegionCodeDomain
    strInsertStatement = AppendValues(strInsertStatement, "RegionCodeDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "RegionCodeDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objRegionCodeDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(objCityNameDomain) then 
  if Not objCityNameDomain is Nothing then 
    cmd.Parameters.Append objCityNameDomain
    strInsertStatement = AppendValues(strInsertStatement, "CityNameDomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "CityNameDomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objCityNameDomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(objCreationDate) then 
  if Not objCreationDate is Nothing then 
    cmd.Parameters.Append objCreationDate
    strInsertStatement = AppendValues(strInsertStatement, "CreationDate")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "CreationDate = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objCreationDate " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if

if isobject(objWHOISName) then 
  if Not objWHOISName is Nothing then 
    cmd.Parameters.Append objWHOISName
    strInsertStatement = AppendValues(strInsertStatement, "WHOISName")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "WHOISName = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objWHOISName " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if
if isobject(objIPaddress) then 
  if Not objIPaddress is Nothing then 
    cmd.Parameters.Append objIPaddress
    strInsertStatement = AppendValues(strInsertStatement, "IPaddress")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "IPaddress = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objIPaddress " & cmd.Parameters.item(cmd.Parameters.count -1)
	if BoolDebugDomainSQL = True then msgbox "strUpdateValue=" & strUpdateValue
  end if
end if
if isobject(objETdomain) then 
  if Not objETdomain is Nothing then 
    cmd.Parameters.Append objETdomain
    strInsertStatement = AppendValues(strInsertStatement, "ETdomain")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "ETdomain = ?")
    if BoolDebugDomainSQL = True then msgbox "adding objETdomain " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if  
if isobject(ObjXForce) then 
  if Not ObjXForce is Nothing then 
    cmd.Parameters.Append ObjXForce
    strInsertStatement = AppendValues(strInsertStatement, "XForce")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "XForce = ?")
    if BoolDebugDomainSQL = True then msgbox "adding ObjXForce " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if  

if isobject(ObjSinkhole) then 
  if Not ObjSinkhole is Nothing then 
    cmd.Parameters.Append ObjSinkhole
    strInsertStatement = AppendValues(strInsertStatement, "Sinkhole")
    strInsertValue = AppendValues(strInsertValue, "?")
    strUpdateValue = AppendValues(strUpdateValue, "Sinkhole = ?")
    if BoolDebugDomainSQL = True then msgbox "adding ObjSinkhole " & cmd.Parameters.item(cmd.Parameters.count -1)
  end if
end if 
if sSQL = "INSERT INTO DomainVend(" then
  sSQL = "INSERT INTO DomainVend(" & strInsertStatement & ") VALUES (" & strInsertValue & ");"
else
  sSQL = "UPDATE DomainVend SET " & strUpdateValue & " WHERE DomainName = ?"
  'msgbox cmd.Parameters.count
  'msgbox sSQL
  
  set objparameter = cmd.createparameter("@DomainName", 129, 1, len(strdomainName),strdomainName)
  cmd.Parameters.Append objparameter

end if
cmd.CommandText = sSQL
'msgbox sSQL
'msgbox cmd.Parameters.count
'for workplease = 0 to cmd.Parameters.count -1
'      msgbox cmd.Parameters.item(workplease)
'    next
cmd.execute
set cmd = nothing
end sub


Function ConvertToUTC(strDateTime, intOffset)
       'convert to UTC
        intOffset = (intOffset) * -1

        ConvertToUTC = DateAdd("n", intOffset, strDateTime)
End Function


Sub LoadAlphabet
DictAlpabet.add 1,"A"
DictAlpabet.add 2,"B"
DictAlpabet.add 3,"C"
DictAlpabet.add 4,"D"
DictAlpabet.add 5,"E"
DictAlpabet.add 6,"F"
DictAlpabet.add 7,"G"
DictAlpabet.add 8,"H"
DictAlpabet.add 9,"I"
DictAlpabet.add 10,"J"
DictAlpabet.add 11,"K"
DictAlpabet.add 12,"L"
DictAlpabet.add 13,"M"
DictAlpabet.add 14,"N"
DictAlpabet.add 15,"O"
DictAlpabet.add 16,"P"
DictAlpabet.add 17,"Q"
DictAlpabet.add  18,"R"
DictAlpabet.add 19,"S"
DictAlpabet.add 20,"T"
DictAlpabet.add 21,"U"
DictAlpabet.add 22,"V"
DictAlpabet.add 23,"W"
DictAlpabet.add 24,"X"
DictAlpabet.add 25,"Y"
DictAlpabet.add 26,"Z"
DictAlpabet.add 27,"AA"
DictAlpabet.add 28,"AB"
DictAlpabet.add 29,"AC"
DictAlpabet.add 30,"AD"
DictAlpabet.add 31,"AE"
DictAlpabet.add 32,"AF"
DictAlpabet.add 33,"AG"
DictAlpabet.add 34,"AH"
DictAlpabet.add 35,"AI"
DictAlpabet.add 36,"AJ"
DictAlpabet.add 37,"AK"
DictAlpabet.add 38,"AL"
DictAlpabet.add 39,"AM"
DictAlpabet.add 40,"AN"
DictAlpabet.add 41,"AO"
DictAlpabet.add 42,"AP"
DictAlpabet.add 43,"AQ"
DictAlpabet.add 44,"AR"
DictAlpabet.add 45,"AS"
DictAlpabet.add 46,"AT"
DictAlpabet.add 47,"AU"
DictAlpabet.add 48,"AV"
DictAlpabet.add 49,"AW"
DictAlpabet.add 50,"AX"
DictAlpabet.add 51,"AY"
DictAlpabet.add 52,"AZ"
end sub


Function RemoveInvalidFromDomain(strInvalidDomainName)
BoolInvalidFound = False
BoolRecordValid = False
StrValidDomain = ""
'msgbox "Domain name passed:" & strInvalidDomainName
for intDomainChar = 1 to len(strInvalidDomainName)
  if BoolInvalidFound = False then
    if CheckInvalidChars(mid(strInvalidDomainName, intDomainChar, 1)) = True then
        BoolInvalidFound = True 
    end if
    
  elseif BoolRecordValid = True then
    StrValidDomain = StrValidDomain & mid(strInvalidDomainName, intDomainChar, 1)
    if CheckInvalidChars(mid(strInvalidDomainName, intDomainChar, 1)) = True then
      BoolRecordValid = False
      StrValidDomain = ""
      'msgbox "invalid char found"
    end if
  elseif mid(strInvalidDomainName, intDomainChar, 1) = "." then
    BoolRecordValid = True
    'msgbox "period found"
  end if  
next
if StrValidDomain <> "" then
  'msgbox "StrValidDomain=" & StrValidDomain
  if instr(StrValidDomain, ".") > 0 then
    arrayTmpCountDomain = split(StrValidDomain, ".")
    if ubound(arrayTmpCountDomain) > 0 then
      RemoveInvalidFromDomain = StrValidDomain
    else
      RemoveInvalidFromDomain = strInvalidDomainName
    end if
  else
    RemoveInvalidFromDomain = strInvalidDomainName
  end if
else
  RemoveInvalidFromDomain = strInvalidDomainName
end if
end Function

Function CheckInvalidChars(strDomainChar)
strInvalidChars = "' + , | ! £ $ % & / ( ) = ? ^ * ç ° § ; : _ > ] [ @ ); - " & Chr(34)
arrayInvalid = split(strInvalidChars, " ")
    for each invalidChar in arrayInvalid
      if strDomainChar = invalidChar then 
        CheckInvalidChars = True 
        'msgbox "invalid char found"
        exit Function
      end if
    next
    CheckInvalidChars = False
end function


Function ReturnSQLiteItem(sSQL, strQueryItem, strReturnName)
if BoolUseSQLite = False then exit function
'msgbox sSQL & "|" &  strQueryItem & "|" &  strReturnName
Set Recordset = CreateObject("ADODB.Recordset")
Set cmd = Nothing
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
   set objparameter0 = cmd.createparameter("@VarHash", 129, 1, len(strQueryItem),strQueryItem)

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

Function DetectionNameHeader()
'create header row for IP/Domain detection names
if cint(intDetectionNameCount) > 0 and BoolDisableVTlookup = False then 'only track detection names when VirusTotal is enabled.
	'msgbox intDetectionNameCount & " -1 + " & intaddDNameCount
		intTmpUboundDcount = cint(intDetectionNameCount) -1 + intaddDNameCount
		'msgbox "headerrowcount=" & intTmpUboundDcount
	for CountArrayDname = 0 to intTmpUboundDcount
		if strTmpDnamesHeader = "" then
		  strTmpDnamesHeader = "|Detection Name " & (CountArrayDname + 1)
		else
		  strTmpDnamesHeader = strTmpDnamesHeader & "|" & "Detection Name " & (CountArrayDname + 1)
		end if
	next
else
  strTmpDnamesHeader = ""
end if
DetectionNameHeader = strTmpDnamesHeader
end function



Function DetectionNameSSline(strVThashItem, intVTCategory)
if cint(intDetectionNameCount) < 1 or BoolDisableVTlookup = True then exit function
if  BoolCreateSpreadsheet = false then exit function
'msgbox "DetectionNameSSline is looking up " & strVThashItem
strTmpDnamesLineE = ""

strTmpVTresults = VTHashLookup(strVThashItem)
If InStr(strTmpVTresults, chr(34) & "https://www.virustotal.com/api/v3/") Then 
	boolVT_V3 = True   
else
	boolVT_V3 = False
end if
inLoopCounter = inLoopCounter + 1
If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 

'Update highest positive detection for specified category
intTmpPositives = getPositiveDetections(strTmpVTresults)
if isnumeric(intTmpPositives) then
  UpdateVTPositives intVTCategory, intTmpPositives
else
  msgbox "Unable to get total number of positive detections from VirusTotal."
end if

intHashlookupCount = intHashlookupCount + 1
'msgbox "strVTAPIresponse=" & strTmpVTresults
setCommonDetectionName strTmpVTresults
'create spreadsheet line output for IP/Domain detection names
'msgbox "ArrayDnameLineE=" & ubound(ArrayDnameLineE)
'msgbox "intaddDNameCount=" & intaddDNameCount
if cint(intDetectionNameCount) -1 + intaddDNameCount  <= ubound(ArrayDnameLineE) then 'check don't go out of the array
	intTmpUboundDcount = cint(intDetectionNameCount) -1 + intaddDNameCount
else'don't go out of the array
	intTmpUboundDcount = ubound(ArrayDnameLineE)
end if
if cint(intDetectionNameCount) > 0 then
	for CountArrayDname = 0 to intTmpUboundDcount 'build row of detection names
		if strTmpDnamesLineE = "" then
		  strTmpDnamesLineE = "|" & ArrayDnameLineE(CountArrayDname)
		else
		  strTmpDnamesLineE = strTmpDnamesLineE & "|" & ArrayDnameLineE(CountArrayDname)
		end if
	next
	if cint(intDetectionNameCount) -1 + intaddDNameCount  > ubound(ArrayDnameLineE) then 'add missing columns, if any, to the row output
		for CountArrayDname = ubound(ArrayDnameLineE) +1 to cint(intDetectionNameCount) -1 + intaddDNameCount
			strTmpDnamesLineE = strTmpDnamesLineE & "|" 
		next
	end if

else
  strTmpDnamesLineE = ""
end if
if BoolDebugTrace = True then logdata strDebugPath & "\VT_IPdomain_hashlist.txt", strVThashItem & "|" & strTmpDnamesLineE ,BoolEchoLog
DetectionNameSSline = strTmpDnamesLineE
end Function

sub setCommonDetectionName(strVTAPIresponse) 'performs malware scoring, sets the detection name and detection type
Dim intDnameCount
Dim DicTmpPUPnames: Set DicTmpPUPnames = CreateObject("Scripting.Dictionary")
Dim DicTmpHkTlnames: Set DicTmpHkTlnames = CreateObject("Scripting.Dictionary")
'msgbox "strVTAPIresponse=" & strVTAPIresponse
if  BoolCreateSpreadsheet = false then exit sub

' v2 positive detection
if instr(strVTAPIresponse,chr(34) & ": {" & chr(34) & "detected" & chr(34) & ": true, ") > 0 or _ 
 (instr(strVTAPIresponse,chr(34) & "last_analysis_stats" & chr(34) & ": {") > 0 and instr(strVTAPIresponse,chr(34) & "malicious" & chr(34) & ": 0,") = 0) Then 'v3 positive detection
    'positive detections
      intTmpMalScore = 0
      IntTmpPUA_Score = 0
      IntTmpHkTlScore = 0
      IntTmpGenericScore = 0
      IntBitDefCount = 0
      intBitDefComp = 0
  if instr(strVTAPIresponse,chr(34) & "result" & chr(34) & ": " & chr(34)) then
      ArrayDetectionNamez = split(strVTAPIresponse,chr(34) & "result" & chr(34) & ": " & chr(34))
      ArrayDetectionNames = BuildArrayWithoutEndQuote(ArrayDetectionNamez)

      
      'use keyword check for sorting out PUA from hackertool
      for each strDetectionName in ArrayDetectionNames
        if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", "Checking PUP or HKTL: " & strDetectionName, false
        strTmpKWretrned = CheckKeyWords(strDetectionName)
        if strTmpKWretrned <> "" then
          if strDetectionKWResults = "" then
            strDetectionKWResults = strTmpKWretrned
          else
            strDetectionKWResults = strDetectionKWResults & "|" & strTmpKWretrned
          end if
        end if
      next
      
      'msgbox "ArrayDetectionNames=" & ubound(ArrayDetectionNames)
      intDnameCount = 1
      'perform pre check for unknown PUA/PUP names and add to dictionary
	  intDnameLocation = 0
      for each strDetectionName in ArrayDetectionNames
		intDnameLocation = intDnameLocation + 1
        if BoolDebugTrace = True then LogData strDebugPath & "\dname_r.log", strDetectionName, false
        'check if detection name is hacker tool or grayware for name categorization
        if graywareKeyWords(strDetectionName) <> "" then 
          BoolPUPdetected = False
          BoolHkTlDetected = True
          if BoolDebugTrace = True then LogData strDebugPath & "\dname_r.log", strDetectionName & ": HKTL-" & graywareKeyWords(strDetectionName), false
        elseif PUAKeyWords(lcase(strDetectionName)) <> "" then 
          BoolPUPdetected = True
          BoolHkTlDetected = false
          if BoolDebugTrace = True then LogData strDebugPath & "\dname_r.log", strDetectionName & ": PUP-" & PUAKeyWords(lcase(strDetectionName)), false
        else
          BoolPUPdetected = False
          BoolHkTlDetected = False
        end if

	  strTmpPUANames =  lcase(VTnameDetect(lcase(strDetectionName), 0)) 'attempts to resolve the detection name

	  if instr(strTmpPUAName, "|") = 0 then strTmpPUAName = strTmpPUAName & "|"
	  arrayPUANames = split(strTmpPUANames, "|")
	  for each strTmpPUAName in arrayPUANames
		'msgbox "strTmpPUAName=" & strTmpPUAName & vbcrlf & "GenericKeyWords(lcase(strTmpPUAName))=" & GenericKeyWords(lcase(strTmpPUAName)) & _
		'vbcrlf & "MalwareKeyWordScore(strTmpPUAName)=" & MalwareKeyWordScore(strTmpPUAName) & vbcrlf & _
		'"graywareKeyWords(strTmpPUAName) = " & graywareKeyWords(strTmpPUAName)
		
		'record detection names
		if strTmpPUAName <> "" and GenericKeyWords(lcase(strTmpPUAName)) < 1 and MalwareKeyWordScore(strTmpPUAName) < 1 and _
		 graywareKeyWords(strTmpPUAName) = "" then 'exclude common names 
		  'msgbox "Name passed requirements: " & strTmpPUAName
		  'only parse bit defender engine names once 
		  if IntBitDefCount = 1 or IntBitDefCount = intBitDefComp then 'if not equal then is name came from the bit defender detection engine 
			if DicTmpDnames.exists(strTmpPUAName) = false then 
			  DicTmpDnames.add strTmpPUAName, 0
			   if BoolDebugTrace = True then LogData strDebugPath & "\dname.log", strTmpPUAName, false
			else
			  DicTmpDnames.item(strTmpPUAName) = DicTmpDnames.item(strTmpPUAName) + 1
			end if   
			if BoolHkTlDetected = True then 'record temporary HackerTool names
			  if DicTmpHkTlnames.exists(strTmpPUAName) = false then 
				DicTmpHkTlnames.add strTmpPUAName, 0
			  else
				DicTmpHkTlnames.item(strTmpPUAName) = DicTmpHkTlnames.item(strTmpPUAName) + 1
			  end if                   
			elseif BoolPUPdetected = True and DicTmpHkTlnames.exists(strTmpPUAName) = false then 'record temporary PUP names
			  if DicTmpPUPnames.exists(strTmpPUAName) = false then 
				DicTmpPUPnames.add strTmpPUAName, 0
			  else
				DicTmpPUPnames.item(strTmpPUAName) = DicTmpPUPnames.item(strTmpPUAName) + 1
			  end if   
			end if
		  end if
		   if BoolDebugTrace = True then LogData strDebugPath & "\bitdef.log", strDetectionName & "|" , false
		elseif GenericKeyWords(lcase(strTmpPUAName)) < 1 then 'contains common naming types
		  'record detection name types
		  if IntBitDefCount = 1 or IntBitDefCount = intBitDefComp then 'if not equal then is name that came from the bit defender detection engine 
		   DetectionTypeTrack strTmpPUAName
 
		  end if
		end if
	  next

        if CheckBitDefenderEngines(ArrayDetectionNamez(intDnameLocation)) = True then 
          IntBitDefCount = IntBitDefCount + 1
        else
          intBitDefComp = IntBitDefCount
        end if
      next

      TmpCompareScore = 0 
      'calculate the total HKTL score
      for each strUniqueDname in DicTmpHkTlnames 'dict of hacker tool names and their score.
        TmpCompareScore = TmpCompareScore + DicTmpHkTlnames.item(strUniqueDname) 
      next
      'parse hacker tool names found and record ones with a score of 3 or higher
      for each strUniqueDname in DicTmpHkTlnames
        if BoolDebugTrace = True then LogData strDebugPath & "\PUP.log", "HKTL|" & strUniqueDname & "|" & DicTmpHkTlnames.item(strUniqueDname) & "|" & TmpCompareScore, false
        if 2 < DicTmpDnames.item(strUniqueDname) and TmpCompareScore > 2 then
        'record HackerTool names
          if BoolDebugTrace = True then LogData strDebugPath & "\PUP.log", "HKTL|" & strTmpPUAName & "|" & strDetectionName & "|" & TmpCompareScore, false
          if strUniqueDname <> "" Then
            if DictHktlNames.exists(strUniqueDname) = False then 'add unique name to dict and dat file
              DictHktlNames.add strUniqueDname, DicTmpDnames.item(strUniqueDname) 'we use the score for the name as it is the same or greater than DictHktlNames
              LogData strCachePath & "\hktl.dat", strUniqueDname & "|" & DicTmpDnames.item(strUniqueDname), false
            end if
          end if           
        end if          
      next

       TmpCompareScore = 0 
      'calculate the total PUP score
      for each strUniqueDname in DicTmpPUPnames
        TmpCompareScore = TmpCompareScore + DicTmpPUPnames.item(strUniqueDname) 
      next         
      'parse PUA/PUP names found and record ones with a score of 3 or higher
      for each strUniqueDname in DicTmpPUPnames
        if BoolDebugTrace = True then LogData strDebugPath & "\PUP.log", "PUP|" & strUniqueDname & "|" & DicTmpPUPnames.item(strUniqueDname)& "|" & TmpCompareScore, false
        if 2 < DicTmpDnames.item(strUniqueDname) and TmpCompareScore > 2 then
        'record PUA names
          if BoolDebugTrace = True then LogData strDebugPath & "\PUP.log", "PUP|" & strTmpPUAName & "|" & strDetectionName & "|" & TmpCompareScore, false
          if strUniqueDname <> "" Then
            if DictPUANames.exists(strUniqueDname) = False then 'if not in dat file add it
              DictPUANames.add strUniqueDname, DicTmpDnames.item(strUniqueDname)
              LogData strCachePath & "\PUP.dat", strUniqueDname & "|" & DicTmpDnames.item(strUniqueDname), false
            end if
          end if           
        end if          
      next
      'msgbox "DicTmpDnames.count = " & DicTmpDnames.count
      'output excel entry for detection name
      for each strUniqueDname in DicTmpDnames
		'msgbox strUniqueDname
		 DetectNameWatchlist strUniqueDname 'check against detection name watchlist and populate strDnameWatchLineE

		 if BoolDebugTrace = True then LogData strDebugPath & "\dnames.log", strUniqueDname & "|" & DicTmpDnames.item(strUniqueDname) , false
         intAmplifyDNscore = 0
         'favor Microsoft detection name
         if instr(strVTAPIresponse,"Microsoft" & chr(34) & ": {" & chr(34) & "detected" & chr(34) & ": true, ") then 'Microsoft positive detection
			   strTmpVND_Compare = ResolveVendorDetectionName("Microsoft")
			   if instr(strTmpVND_Compare, "/") then strTmpVND_Compare = getdata(strTmpVND_Compare, ".", "/")
			  'compare detection names
			  if instr(lcase(strTmpVND_Compare),strUniqueDname) then 
				intAmplifyDNscore = 1
				'msgbox "amplify"
			  end if
         end if
		 'amplify common family names
		 'msgbox "dictFamilyNames.exists(" & strUniqueDname & ") = " & dictFamilyNames.exists(strUniqueDname)
		 if dictFamilyNames.exists(strUniqueDname) = True then
			
			intAmplifyDNscore = intAmplifyDNscore +1
		 end if
		 
        if intDnameCount < DicTmpDnames.item(strUniqueDname) + intAmplifyDNscore then
          strDetectNameLineE = "|" & strUniqueDname
          intDnameCount = DicTmpDnames.item(strUniqueDname) + intAmplifyDNscore             
        end if
      next

	  'Detection names associated with IP/domain
      if cint(intDetectionNameCount) > 0 and DicTmpDnames.count > 0 and intVTListDataType = 1 then
        SortDictionary DicTmpDnames, dictItem 'Sorts dictionary by item count (not key)
        'msgbox "DicTmpDnames count=" & DicTmpDnames.count
		'msgbox "ArrayDnameLineE=" & ubound(ArrayDnameLineE)
		strTmpUboundLimit = cint(intDetectionNameCount) -1 + intaddDNameCount
		if strTmpUboundLimit >  DicTmpDnames.count then  strTmpUboundLimit = DicTmpDnames.count -1
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "ubound ArrayDnameLineE=" & ubound(ArrayDnameLineE) ,BoolEchoLog 
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "strTmpUboundLimit=" & strTmpUboundLimit ,BoolEchoLog 
		if strTmpUboundLimit > -1 Then
			for CountArrayDname = 0 to strTmpUboundLimit 'loop through count to populate ArrayDnameLineE
				if CountArrayDname = DicTmpDnames.count then exit for ' don't go over dict count for DicTmpDnames
			  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "ArrayDnameLineE(" & CountArrayDname & ")=" & ArrayDnameLineE(CountArrayDname) ,BoolEchoLog 
			  'clipping level
			  if cint(intClippingLevel) < cint(DicTmpDnames.item(DicTmpDnames.keys()(DicTmpDnames.count -1 -CountArrayDname))) + intAmplifyDNscore then
				if strTmpUboundLimit > -1 and DicTmpDnames.count -1 -CountArrayDname > -1 Then ArrayDnameLineE(CountArrayDname) = DicTmpDnames.keys()(DicTmpDnames.count -1 -CountArrayDname)
			  end if
			next
		end if
      end if
      
      
      intDnameCount = 1
      'output excel entry for detection type name
      if DictTypeNames.count > -1 then 
		  for each strUniqueDname in DictTypeNames
			if BoolDebugTrace = True then LogData strDebugPath & "\dtnames.log", strUniqueDname & "|" & DictTypeNames.item(strUniqueDname) , false
			if (strUniqueDname = "trojan" or strUniqueDname = "troj") and DictTypeNames.item(strUniqueDname) > 3 then BoolTrojanType = True 'favor other name types
			if intDnameCount < DictTypeNames.item(strUniqueDname) and BoolTrojanType = false then
			  StrDetectionTypeLineE = "|" & strUniqueDname
			  intDnameCount = DictTypeNames.item(strUniqueDname)
			end if
		  next
	  end if
      if (StrDetectionTypeLineE = "|" or StrDetectionTypeLineE = "") and BoolTrojanType = True then StrDetectionTypeLineE = "|trojan"
        intVTpositiveDetections = getPositiveDetections(strVTAPIresponse)
        intVTpositiveDetections = cint(intVTpositiveDetections)
        intTmpMalScore = 0
        IntTmpPUA_Score = 0
        IntTmpHkTlScore = 0
        IntTmpGenericScore = 0

        'perform keyword check            
        for each strDetectionName in ArrayDetectionNames
          if BoolDebugTrace = True then logdata strDebugPath & "\VT_h_scoring" & "" & ".txt", "Keyword check", false
          strTmpKWretrned = CheckKeyWords(strDetectionName)
          if strTmpKWretrned <> "" then
            if strDetectionKWResults = "" then
              strDetectionKWResults = strTmpKWretrned
            else
              strDetectionKWResults = strDetectionKWResults & "|" & strTmpKWretrned
            end if
          end if
        next
      end if

else'no positive detections
	strDetectNameLineE = "|"
end if  

end sub

Function BuildArrayWithoutEndQuote (strArrayDnameQuote)
reDim arrayTmpReturn(ubound(strArrayDnameQuote) -1)
intBuildArrayCount = 0
for each strDetectionNquote in strArrayDnameQuote
	strDetectionNquote = left(strDetectionNquote, instr(strDetectionNquote,chr(34)))
	'msgbox strDetectionNquote & "|" & right(strDetectionNquote,3)
	if right(strDetectionNquote, 1) = chr(34) then
		strDetectionNquote = left(strDetectionNquote, len(strDetectionNquote) -1)
	end if
	'msgbox len(strDetectionNquote)
	if len(strDetectionNquote) > 1 then
		if left(strDetectionNquote,1) <> "{" then
			'msgbox strDetectionNquote
			arrayTmpReturn(intBuildArrayCount) = strDetectionNquote
			intBuildArrayCount = intBuildArrayCount + 1
		end if
	end if
next
BuildArrayWithoutEndQuote = arrayTmpReturn
end function

Function SortDictionary(objDict,intSort)'https://support.microsoft.com/en-us/kb/246067
Dim strDict()
Dim objKey
Dim strKey,strItem
Dim X,Y,Z
Z = objDict.Count 'count of items in passed Dict
If Z > 1 Then
  ReDim strDict(Z,2)
  X = 0
  For Each objKey In objDict
      strDict(X,dictKey)  = CStr(objKey)
      strDict(X,dictItem) = CStr(objDict(objKey))
      X = X + 1
  Next
  For X = 0 to (Z - 2)
    For Y = X to (Z - 1)
      If StrComp(strDict(X,intSort),strDict(Y,intSort),vbTextCompare) > 0 Then
          strKey  = strDict(X,dictKey)
          strItem = strDict(X,dictItem)
          strDict(X,dictKey)  = strDict(Y,dictKey)
          strDict(X,dictItem) = strDict(Y,dictItem)
          strDict(Y,dictKey)  = strKey
          strDict(Y,dictItem) = strItem
      End If
    Next
  Next
  objDict.RemoveAll
  For X = 0 to (Z - 1)
    objDict.Add strDict(X,dictKey), strDict(X,dictItem)
  Next
End If
End Function


Function VTHashLookup(strVThashItem)
if ishash(strVThashItem) = false then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VTHashLookup - item is not a hash:" & strVThashItem,False 
	exit function
end if

 if BoolDisableCacheLookup = False then
  strVTresponseText = CacheLookup("", "\vt\", strVThashItem, intHashCacheThreashold)
	if strVTresponseText <> "" then
		VTHashLookup = strVTresponseText
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " VTHashLookup Cached - " & strVThashItem ,false
		inLoopCounter = inLoopCounter -1 'zero out loop as we didn't utilize the API
    	If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " Didn't utilize API  inLoopCounter=" & inLoopCounter,False 
		exit function
	end if
 end if

lookupDelay
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.open "GET", "https://www.virustotal.com/api/v3/files/" & strVThashItem, False
objHTTP.setRequestHeader "x-apikey", strAPIKey
if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt",Date & " " & Time & " Looking up " & strVThashItem  ,BoolEchoLog       
if BoolDebugTrace = True then logdata strDebugPath & "\VT_time" & "" & ".txt",Date & " " & Time & " Looking up " & strVThashItem  ,BoolEchoLog   


  on error resume next
  objHTTP.send

  strDateLookupTrack = Now 'set the date time when last lookup was performed for rate limit delay
  if err.number <> 0 then
	if intVTErrorCount > 3 then
	  objShellComplete.popup "Error #" & err.number & " - " & err.description & vbcrlf & vbcrlf & "Will attempt to submit to VirusTotal again.  If problems persist check connectivity", 30
	  if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Error #" & err.number & " - " & err.description,BoolEchoLog 
	  intVTErrorCount = 0
	else
	  intVTErrorCount = intVTErrorCount + 1
	  wscript.sleep 15000
	end if
	inLoopCounter = inLoopCounter + 1
	VTHashLookup = VTHashLookup(strVThashItem)
	exit function
  end if


if objHTTP.status = 204 then
  if BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " VTHashLookup - VirusTotal returned 204 status code for exceeded rate limit. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
  objShellComplete.popup "204 HTTP status code was returned. You have exceed the API request rate limit." & vbcrlf & vbcrlf & "Will attempt to submit to VirusTotal again after delaying for " & intDelayBetweenLookups & " seconds.  If problems persist check connectivity", 16
  logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VTHashLookup - VirusTotal returned 204 status code for exceeded rate limit. Sleeping for " & intDelayBetweenLookups & " seconds.",False 
  'wscript.sleep 30000
  inLoopCounter = inLoopCounter + 1
  VTHashLookup = VTHashLookup(strVThashItem)
  exit function
elseif objHTTP.responseText = "" Then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VTHashLookup - VirusTotal returned no data with " & objHTTP.status  & " status code. Sleeping to delay.",False 
	inLoopCounter = inLoopCounter + 1
  VTHashLookup = VTHashLookup(strVThashItem)
  exit function
ElseIf objHTTP.status <> 200 Then
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VTHashLookup - VirusTotal returned " & objHTTP.status  & " status code with the following response: " & objHTTP.responseText,False 
End if

VTHashLookup = objHTTP.responseText

'save VT results to cache
if BoolDisableCaching = False and BoolCacheRelatedHashLookups = True then CacheLookup objHTTP.responseText, "\vt\", strVThashItem, 45
end Function

sub lookupDelay
If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " inLoopCounter=" & inLoopCounter,False 
if inLoopCounter >= 1 then
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_time" & "" & ".txt", "Sleeping " & datediff("s", strDateLookupTrack, now) & " < " & (intDelayBetweenLookups \ 1000) ,BoolEchoLog 
	if datediff("s", strDateLookupTrack, now) < (intDelayBetweenLookups \ 1000) then 
	  intSleep = intDelayBetweenLookups + (datediff("s", now, strDateLookupTrack) * 1000) 'subtract time that has passed
		if BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " intSleep = " & intSleep & "  intDelayBetweenLookups=" & intDelayBetweenLookups & "  offset=" &  (datediff("s", now, strDateLookupTrack) * 1000) & "  strDateLookupTrack=" & strDateLookupTrack,False 
	  if intSleep > 0 then wscript.sleep intSleep
	Else
		If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " Delay called but time has passed. " & "  strDateLookupTrack=" & strDateLookupTrack,False 
	End if  
else
	If BoolDebugTrace = True then logdata strDebugPath & "\VT_time.txt", Date & " " & Time & " Delay called but inLoopCounter was not greater than zero. " & "  strDateLookupTrack=" & strDateLookupTrack,False 
end if
inLoopCounter = 0


end sub

Function MatchURLwatchList (strWLstoredResults, strWLcheck) 
Dim WLreturnValue
WLreturnValue = ""
'msgbox "strWLstoredResults=" & strWLstoredResults
if dictURLWatchList.count = 0 then exit function
for each WatchItem in dictURLWatchList
	'msgbox "WatchItem=" & WatchItem
  if BoolURLWatchLlistRegex = True then
    Set re = new regexp  'Create the RegExp object 'more info at https://msdn.microsoft.com/en-us/library/ms974570.aspx

    re.Pattern = WatchItem
    re.IgnoreCase = true
    WLRegXresult = re.Test(strWLcheck)
	'msgbox "regex match=" & WLRegXresult & " for " & WatchItem
    if WLRegXresult = True then
      WLreturnValue = concatenateItem(strWLstoredResults, WatchItem, "   " )
	  WLreturnValue = replace(WLreturnValue, "|", "^or^")
    end if
  else
    if instr(strWLcheck, WatchItem) > 0 then
      WLreturnValue = concatenateItem(strWLstoredResults, WatchItem, "   " )    
    end if
  end if
next
'msgbox "MatchURLwatchList =" & WLreturnValue
MatchURLwatchList = WLreturnValue
end function


Function MatchIpDwatchLIst(strIpDitem)
Dim strIpDreturn: strIpDreturn = ""
'msgbox "dictIPdomainWatchList.count=" & dictIPdomainWatchList.count 
if dictIPdomainWatchList.count > 0 then 
	if dictIPdomainWatchList.exists(strIpDitem) then 
		'msgbox "strIpDitem=" & strIpDitem
		if dictIPdomainWatchList.item(strIpDitem) <> "" then 
			strIpDreturn = dictIPdomainWatchList.item(strIpDitem) & "/" & strIpDitem

		else
			strIpDreturn = strIpDitem
		end if
	end if
end if

MatchIpDwatchLIst = concatenateItem(strIpDwatchLineE, strIpDreturn, "^")
end function


Function concatenateItem(strClist, strCitem, strCseparator)
'msgbox "strClist=" & strClist
Dim dictCsort: Set dictCsort = CreateObject("Scripting.Dictionary")
dim strTmpClist
if strClist = "" then
	strTmpClist = strCitem
elseif strCitem <> "" Then

	strTmpClist = strClist & strCseparator & strCitem

	ArrayTmpClist = split(strTmpClist, strCseparator)
	'msgbox "splitting"
	For each strTmpCitem in ArrayTmpClist
		if dictCsort.exists(strTmpCitem) = False then 
			dictCsort.add strTmpCitem, ""
			'msgbox "adding item to dict " & strTmpCitem
		end if	
	Next
	'msgbox "dictCsort.count=" & dictCsort.count
	for each strTmpCitem in dictCsort
		if strTmpNewClist = "" Then
			strTmpNewClist = strTmpCitem
		else
			strTmpNewClist = strTmpNewClist & strCseparator & strTmpCitem
		end if
	Next
	strTmpClist = strTmpNewClist
else'no item to add
	strTmpClist = strClist
end if
'msgbox "concatenateItem =" & strTmpClist
concatenateItem = strTmpClist
end Function

Function CheckTIA(strVendorName, strDetectionName)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
'threatintelligenceaggregator.org
strAVEurl = "http://threatintelligenceaggregator.org/api/v1/" & strVendorName & "/?name=" & strDetectionName & "&ApiKey=" & strTIAkey
objHTTP.open "GET", strAVEurl
'header is preferred method for API key vs commented out query string above
'objHTTP.setRequestHeader "ApiKey", strTIAkey 

on error resume next
  objHTTP.send
  if objHTTP.status = 402 then
	wscript.sleep 59000
	CheckTIA = CheckTIA(strVendorName, strDetectionName)
	exit function
  end if
  if err.number <> 0 then
    logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " TIA lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
on error goto 0  

strTIAresponse= objHTTP.responseText
if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", strVendorName & ":" & strDetectionName & "|" & strAVEurl & " - " & strTIAresponse,BoolEchoLog 

if strTIAresponse = "Request limit exceeded" then
	wscript.sleep 10000
	CheckTIA = CheckTIA(strVendorName, strDetectionName)
	exit function
end if

'json should contain detection name
if instr(strTIAresponse,"DetectionName") = 0 and objHTTP.responseText <> chr(34) & "No results found" & Chr(34) then 'don't log TIA no search results returnedthen 
	CheckTIA = "ERROR"
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " TIA lookup for " & strVendorName & " " & strDetectionName & " failed with HTTP error. - " & objHTTP.status & ": " & strTIAresponse ,False 
	exit function
end if

'API should return a detection name if a value was provided
strReturnDN = getdata(strTIAresponse, chr(34), "DetectionName" & Chr(34) & ":" & Chr(34))
if strReturnDN = "" then 
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strReturnDN=" & Chr(34) & Chr(34),BoolEchoLog 
  exit function
end if

'queued entry means limited or no results
intQueue = getdata(strTIAresponse, "}", "Queue" & Chr(34) & ":")
if intQueue <> "null" then
  CheckTIA = "Q"
  if BoolDebugTrace = True and boolEnableTIAqueue = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "Detection name=" & strDetectionName & " CheckTIA=Q  lookupQueue.Count=" & lookupQueue.Count ,BoolEchoLog 
  exit function
end if

if len(strTIAresponse) > 0 then
  strReturnURL = getdata(strTIAresponse, chr(34), "URL" & Chr(34) & ":" & Chr(34))'return reference URL
  if strReturnURL = "" and SignatureDateCheck = True then 
	'return date instead of blank URL
	strDateTime = getdata(strTIAresponse, chr(34), "DateLastSeen" & Chr(34) & ":" & Chr(34))
	if DateTimeCompare(strDateTime, intSigDateRange) = True then strReturnURL = strDateTime
	strDateTime = getdata(strTIAresponse, chr(34), "DateFirstSeen" & Chr(34) & ":" & Chr(34))
	if DateTimeCompare(strDateTime, intSigDateRange) = True then strReturnURL = strDateTime
	strDateTime = getdata(strTIAresponse, chr(34), "DateCreated" & Chr(34) & ":" & Chr(34))
	if DateTimeCompare(strDateTime, intSigDateRange) = True then strReturnURL = strDateTime	
  end if
  if strReturnURL <> "" then 
    CheckTIA = strReturnURL
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strReturnURL=" & strReturnURL,BoolEchoLog 
  End If
else
  'msgbox "failed lookup"
  'No lookup
  CheckTIA = ""
  if objHTTP.responseText <> chr(34) & "No results found" & Chr(34) then 'don't log TIA no search results returned
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " TIA lookup for " & strVendorName & " " & strDetectionName & " failed with HTTP error. - " & objHTTP.status & " " & objHTTP.responseText,False 
  end if
end if
end function


Function DateTimeCompare(strDateTime, intRangeInDays)
strModifiedDateTime = replace(strDateTime, "T", " ")
if isdate(strModifiedDateTime) = false then
	DateTimeCompare = False
	exit function
end if
Comparedate = CDate(strModifiedDateTime)
if datediff("d",Comparedate, now) < intRangeInDays then
	DateTimeCompare = True
else
  DateTimeCompare = False
end if
end function

Function VTvendorParseName(VTresponse, strVendorName, boolEncyclopedia)
if strVendorName = "" then 
	logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " VTvendorParseName was provided a blank vendor name",False 
	exit function 'need a vendor name
end if
if getPositiveDetections(VTresponse) <> 0 then '
	'msgbox strVendorName & " positive detection."
	if boolVT_V3 = True then
		strTmpVendorDetectionName = getdata(VTresponse, "}", chr(34) & strVendorName & chr(34) & ": {")
	else
		strTmpVendorDetectionName = getdata(VTresponse,", " & chr(34) & "update",strVendorName & chr(34) & ": {" & chr(34) & "detected" & chr(34) & ": true, ")
	end if
	strTmpVendorDetectionName = getdata(strTmpVendorDetectionName,chr(34),"result" & chr(34) & ": " & chr(34))
	VTvendorParseName = strTmpVendorDetectionName
	if boolEncyclopedia = True And strTmpVendorDetectionName <> "" then
		StrTmpVendorDetectionURL = Encyclopdia_Cache(strVendorName, strTmpVendorDetectionName)
		if StrTmpVendorDetectionURL <> "" then
		  logdata strDebugPath & "\VT_URLs_" & "" & ".txt", strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL,BoolEchoLog 
		  strThisScanResults = strThisScanResults & strScanDataInfo & vbtab & strTmpVendorDetectionName & " - " & StrTmpVendorDetectionURL & vbcrlf
		end if
				
		if StrTmpVendorDetectionURL = strVendorName then
			if dictUrlOut.exists(strVendorName & "|" & strTmpVendorDetectionName) = False then
				dictUrlOut.add strVendorName & "|" & strTmpVendorDetectionName, strScanDataInfo

			end if
		end if
	End if
end if
end Function



Function IsIPv6(TestString)

    Dim sTemp
    Dim iLen
    Dim iCtr
    Dim sChar
    
    if instr(TestString, ":") = 0 then 
		IsIPv6 = false
		exit function
	end if
    
    sTemp = TestString
    iLen = Len(sTemp)
    If iLen > 0 Then
        For iCtr = 1 To iLen
            sChar = Mid(sTemp, iCtr, 1)
            if isnumeric(sChar) or "a"= lcase(sChar) or "b"= lcase(sChar) or "c"= lcase(sChar) or "d"= lcase(sChar) or "e"= lcase(sChar) or "f"= lcase(sChar) or ":" = sChar then
              'allowed characters for hash (hex)
            else
              IsIPv6 = False
              exit function
            end if
        Next
    
    IsIPv6 = True
    else
      IsIPv6 = False
    End If
    
End Function


Function AlienPulse(strAlienReturn)
' Chr(34) & "extracted_source" & Chr(34) & ":" -this provides a count of pulses
'or "pulse_info": {"count": 3

AlienPulse = getdata(strAlienReturn, ",", "pulse_info" & chr(34) & ": {" & chr(34) & "count" & chr(34) & ": ")

end function

Function AppendValuesList(strAggregate,strAppend,strSeparator)
    if strAggregate = "" then
      strAggregate = strAppend
    else
      strAggregate = strAggregate & strSeparator & strAppend
    end if
AppendValuesList = strAggregate

end Function

Function AlienValidation(strAlienReturn)
'Whitelisted ad network domain ads.ak.facebook.com"
'"Whitelisted domain facebook.com",
'Whitelisted file sharing domain facebook.com
'get validation section
'"validation": [{"source": "ad_network", "message": "Whitelisted ad network domain ads.ak.facebook.com", "name": "Whitelisted ad network domain"}, {"source": "alexa", "message": "Alexa rank: #3", "name": "Listed on Alexa"}, {"source": "filesharing", "message": "Whitelisted file sharing domain facebook.com", "name": "Whitelisted filesharing network domain"}, {"source": "whitelist", "message": "Whitelisted domain facebook.com", "name": "Whitelisted domain"}],
'grab names
'"name": "Whitelisted IP"}]
'^ separated list for Validation column
strAvalidation = getdata(strAlienReturn, "}],", chr(34) & "validation" & chr(34) & ": [{")
'msgbox "Alien Return=" & strAvalidation
if len(strAvalidation) > 10 then
  if instr(strAvalidation, chr(34) & "name" & chr(34) & ": ") = 0 then exit function
  arrayNames = split(strAvalidation, chr(34) & "name" & chr(34) & ": ")
  
  for each validationName in arrayNames
    'msgbox validationName
    if left(validationName,1) = chr(34) and left(validationName,7) <> chr(34) & "source"  then
      'msgbox getdata(validationName,chr(34), chr(34))
      strValidationOut = AppendValuesList(strValidationOut, getdata(validationName,chr(34), chr(34)), "^")
    end if
  next  
end if
AlienValidation = strValidationOut
end function

Sub ProcessAlienVaultPdns(strPdnsURL, pDNSIp)
if strDomainListOut = "|" then strDomainListOut = ""
if strDomainListOut = "" then
	strAlienVaultpDNSReturn = pullAlienVault(strPdnsURL, pDNSIp, "/passive_dns")

	AlienVaultPassiveDNS strAlienVaultpDNSReturn
end if

end sub

Sub AlienVaultPassiveDNS(strPdns)
pDnsCount = 0
'msgbox "strDomainListOut=" & strDomainListOut
if strDomainListOut = "" or strDomainListOut = "|" then
	if instr(strPdns, "{" & chr(34) & "last" & chr(34) & ":") > 0 then
		arraypDNS = split(strPdns, "{" & chr(34) & "last" & chr(34) & ":")
		'msgbox "Passive DNS Count:" & ubound(arraypDNS)
		for each pDNSline in arraypDNS
			pdnsName = getdata(pDNSline, chr(34), chr(34) & "hostname" & chr(34) & ": " & chr(34))
			if pdnsName <> "" then
				if DictTrackDomain(pdnsName) = false then  'only count domains once. This also checks against watchlists
				
					if pDnsCount < 6 then
						strDomainListOut = AppendValuesList(strDomainListOut,pdnsName,";")
					end if
				end if
			end if
			pDnsCount = pDnsCount + 1
		next
	end if
end if
end Sub


Sub ProcessAlienVaultNIDS(strPdnsURL, NIDSip)

strAlienVaultpDNSReturn = pullAlienVault(strPdnsURL, NIDSip, "/nids_list")

AlienVaultNIDS strAlienVaultpDNSReturn


end sub

Sub AlienVaultNIDS(strNIDSlist)
if BoolDebugTrace = True then LogData strDebugPath & "\IP_OTX_NIDS.log",  strNIDSlist, False

AlienNIDScount = getdata(strNIDSlist, ",", chr(34) & "count" & Chr(34) & ": ")

AlienNIDS = ""
NIDScommaList = getdata(strNIDSlist, "]", chr(34) & "results" & Chr(34) & ": [")
if len(NIDScommaList) > 1 then
	if instr(NIDScommaList, ",") > 0 then
		arrayNIDS = split(NIDScommaList, ",")

		for each NIDSitem in arrayNIDS
			NIDSid = getdata(NIDSitem, chr(34), chr(34))
			if pDnsCount = 0 then
				AlienVaultNIDSSignature NIDSid 'Builds signature output

			elseif pDnsCount < 10 then
				AlienVaultNIDSSignature NIDSid 'Builds signature output
				
			else
				exit for
			end if
			pDnsCount = pDnsCount + 1
		next
	else
		NIDSid = getdata(strNIDSlist, chr(34), chr(34) & "results" & Chr(34) & ": [" & CHr(34))
		AlienVaultNIDSSignature NIDSid 'Builds signature output
	end if
	'msgbox AlienNIDScount & "|" & AlienNIDS
end if
end sub

Function AlienVaultNIDSSignature(intNIDS_ID)
if dictNIDScategory.exists(intNIDS_ID) and dictNIDSsigName.exists(intNIDS_ID) then
	NIDS_Category = dictNIDScategory.item(intNIDS_ID)
	NIDS_SigName = dictNIDSsigName.item(intNIDS_ID)

else
	wscript.sleep 0
	strAlienVaultSigReturn = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/nids/", intNIDS_ID, "/general")
	if BoolDebugTrace = True then LogData strDebugPath & "\IP_OTX_NIDS.log",  strAlienVaultSigReturn, False
	NIDS_SigName = getdata(strAlienVaultSigReturn, chr(34), chr(34) & "name" & Chr(34) & ": " & CHr(34))
	'msgbox "signame:" & NIDS_SigName
	logdata strCachePath & "\NIDS_Sig.dat", intNIDS_ID & "|" & NIDS_SigName, false
	dictNIDSsigName.add intNIDS_ID, NIDS_SigName
	NIDS_Category = getdata(strAlienVaultSigReturn, chr(34), chr(34) & "subcategory" & Chr(34) & ": " & CHr(34))
	logdata strCachePath & "\NIDS_Cat.dat", intNIDS_ID & "|" & NIDS_Category, false
	dictNIDScategory.add intNIDS_ID, NIDS_Category
	'msgbox "category:" & NIDS_Category
end if
if NIDS_SigName <> "" then 
	if AlienNIDS = "" then
		AlienNIDS = "|" & NIDS_SigName
	else
		AlienNIDS = AlienNIDS & "^" & NIDS_SigName
	end if
end if
if NIDS_Category <> "" and dictNIDStmpCategory.exists(NIDS_Category) = False then dictNIDStmpCategory.add NIDS_Category, intNIDS_ID

AlienVaultNIDSSignature = NIDS_SigName
end function


Function AlienVaultWhois(strWhoisTmp)

aWhoisReturn = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Org" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "org" & chr(34) & "}")

if aWhoisReturn = "" then aWhoisReturn = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & " Name" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "name" & chr(34) & "}")

if aWhoisReturn = "" then aWhoisReturn = getdata(strWhoisTmp, chr(34), chr(34) & "asn" & chr(34) & ": " & chr(34) )

' set city, region, and country code for spreadsheet output
if strTmpCITlineE = "" or strTmpCITlineE = "|" then
strTmpCITlineE = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & "City" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "city" & chr(34) & "}")
if strTmpCITlineE = "" then'geoip
	strTmpCITlineE = getdata(strWhoisTmp, chr(34), chr(34) & "city" & chr(34) & ": " & chr(34) )
end if
strTmpCITlineE = "|" & CleanupWhoisData(strTmpCITlineE)
end if
'msgbox strTmpCITlineE
if strTmpRNlineE = "" or strTmpRNlineE = "|" then
strTmpRNlineE = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & "State" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "state" & chr(34) & "}")
if strTmpRNlineE = "" then'geoip
	strTmpRNlineE = getdata(strWhoisTmp, chr(34), chr(34) & "region" & chr(34) & ": " & chr(34) )
end if
strTmpRNlineE = "|" & CleanupWhoisData(strTmpRNlineE)
end if
'msgbox strTmpRNlineE
if strTmpCNlineE = "" or strTmpCNlineE = "|" then
strTmpCNlineE = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & "Country" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "country" & chr(34) & "}")
if strTmpCNlineE = "" then 'geoip
	strTmpCNlineE = getdata(strWhoisTmp, chr(34), chr(34) & "country_name" & chr(34) & ": " & chr(34) )
end if
strTmpCNlineE = "|" & CleanupWhoisData(strTmpCNlineE)
end if
'msgbox strTmpCNlineE
if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois Creation Date before being set: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
if strTmpWCO_CClineE = "" or strTmpWCO_CClineE = "|" or len(strTmpWCO_CClineE) < 4 then
  strTmpWCO_CClineE = rgetdata(strWhoisTmp, chr(34), chr(34) & ", " & chr(34) & "name" & chr(34) & ": " & chr(34) & "Creation Date" & chr(34) & ", " & chr(34) & "key" & chr(34) & ": " & chr(34) & "creation_date" & chr(34) & "}")
  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois Creation Date: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
  strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)

else
  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "whois already set Creation Date: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE, false
end if
if strTmpCClineE = "" or strTmpCClineE = "|" then
	strTmpCClineE = "|" & getdata(strWhoisTmp, chr(34), chr(34) & "country_code" & chr(34) & ": " & chr(34) )
	if strTmpCClineE = "" or strTmpCClineE = "|" then
		strTmpCClineE = "|" & getdata(strWhoisTmp, chr(34), chr(34) & "country" & chr(34) & ": " & chr(34) )
	end if
end if

if strTmpCNlineE = "|" and strTmpCClineE = "|" Then
	if instr(strWhoisTmp, "latitude" & chr(34) & ": 35.0,") > 0 and _
	instr(strWhoisTmp, "longitude" & chr(34) & ": 105.0,") > 0 then
		strTmpCNlineE = "United States"
		strTmpCClineE = "US"
	elseif instr(strWhoisTmp, "latitude" & chr(34) & ": 47.0,") > 0 and _
	instr(strWhoisTmp, "longitude" & chr(34) & ": 8.0,") > 0 then
		strTmpCNlineE = "Europe"
		strTmpCClineE = "EU"	
	end if
end if


MoveSSLocationEntries 'check if country code is listed as country name

'check for sinkhole domain
CheckWhoISData strWhoisTmp
if BoolDebugTrace = True then LogData strDebugPath & "\whois_responses.log", "AlienVault response", false
AlienVaultWhois = aWhoisReturn
end function

Sub AlienHashLookup(strAlienHash)
if boolUseAlienVault = True and AlienVaultPulseLine = "" then
  strAlienVaultReturn = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/file/", strAlienHash, "/general")
  AlienVaultPulseLine = AlienPulse(strAlienVaultReturn)
end if
end sub

Function pullAlienVault(strAlienURL, strCheckItem, strSection)
'returns HTTP body

  
  if instr(strAlienURL,"/domain/") > 0 then
    StrValidDomainName = RemoveInvalidFromDomain(strCheckItem)
  else
    StrValidDomainName = strCheckItem
  end if
  Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")

      strAVEurl = strAlienURL & StrValidDomainName &  strSection
   
    'objHTTP.setRequestHeader 
    objHTTP.open "GET", strAVEurl
	if useAlienVapiKey = True then
		objHTTP.setRequestHeader "X-OTX-API-KEY", strAlienVaultkey 
	end if

   
  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " AlienVault lookup failed with HTTP error while querying " & strCheckItem & " - " & err.description,False 
      exit function 
    end if
  on error goto 0  


  if BoolDebugTrace = True then logdata strAlienVaultreportsPath & "\AlienV_" & replace(strData, ":",".") & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  if len(objHTTP.responseText) > 0 then
    pullAlienVault = objHTTP.responseText
  end if
   
  Set objHTTP = Nothing
end Function

sub ProcessAlienURLs(strAlienURLreturn)

if instr(strAlienURLreturn, chr(34) & "domain" & chr(34) & ":") > 0 then 'process domains
	arrayAlienURLs = split(strAlienURLreturn, chr(34) & "domain" & chr(34) & ":")
	intCountOutDomain = 0
	for each AlienURL in arrayAlienURLs

		AlienTmpURL = getdata(AlienURL, chr(34), chr(34))
		if instr(AlienTmpURL, ".") > 0 then
			if DictTrackDomain(AlienTmpURL) = false then  'only count domains once. This also checks against watchlists
				if intCountOutDomain < 6 then

					strDomainListOut = concatenateItem(strDomainListOut, AlienTmpURL, ";")
				end if

			end if 
			
			
			intCountOutDomain = intCountOutDomain +1
		end if
	next
end if

if boolLogURLs = True or dictURLWatchList.count > 0 then 'process URLs
	if instr(strAlienURLreturn, chr(34) & "url" & chr(34) & ":") > 0 then
		arrayAlienURLs = split(strAlienURLreturn, chr(34) & "url" & chr(34) & ":")
		for each AlienURL in arrayAlienURLs

			AlienTmpURL = getdata(AlienURL, chr(34), chr(34))
			if instr(AlienTmpURL, ".") > 0 then
				if boolLogURLs = True then logdata strReportsPath & "\URLs_" & UniqueString & ".log",AlienTmpURL, false
				strURLWatchLineE = MatchURLwatchList(strURLWatchLineE, AlienTmpURL)
			end if
		next
	end if
end if
end sub

Function ispipeorempty(strpipecompare)
if strpipecompare = "|" or strpipecompare = "" then
	ispipeorempty = True
else
	ispipeorempty = False
end if
end function

Function ValueFromIni(strFpath, iniSection, iniKey, currentValue)
returniniVal = ReadIni( strFpath, iniSection, iniKey)
if returniniVal = " " or returniniVal = "" then 
	ValueFromIni = currentValue
	Exit function
end if 
if TypeName(returniniVal) = "String" then
	returniniVal = stringToBool(returniniVal)'convert type to boolean if needed
elseif TypeName(returniniVal) = "Integer" then
	returniniVal = int(returniniVal)'convert type to int if needed
end if
ValueFromIni = returniniVal
end function

Function stringToBool(strBoolean)
if lcase(strBoolean) = "true" then 
	returnBoolean = True
elseif lcase(strBoolean) = "false" then 
	returnBoolean = False
else
	returnBoolean = strBoolean
end if
stringToBool = returnBoolean
end function

Function ReadIni( myFilePath, mySection, myKey ) 'http://www.robvanderwoude.com/vbstech_files_ini.php
    ' This function returns a value read from an INI file
    '
    ' Arguments:
    ' myFilePath  [string]  the (path and) file name of the INI file
    ' mySection   [string]  the section in the INI file to be searched
    ' myKey       [string]  the key whose value is to be returned
    '
    ' Returns:
    ' the [string] value for the specified key in the specified section
    '
    ' CAVEAT:     Will return a space if key exists but value is blank
    '
    ' Written by Keith Lacelle
    ' Modified by Denis St-Pierre and Rob van der Woude

    Dim intEqualPos
    Dim objFSO, objIniFile
    Dim strFilePath, strKey, strLeftString, strLine, strSection

    Set objFSO = CreateObject( "Scripting.FileSystemObject" )

    ReadIni     = ""
    strFilePath = Trim( myFilePath )
    strSection  = Trim( mySection )
    strKey      = Trim( myKey )

    If objFSO.FileExists( strFilePath ) Then
        Set objIniFile = objFSO.OpenTextFile( strFilePath, ForReading, False )
        Do While objIniFile.AtEndOfStream = False
            strLine = Trim( objIniFile.ReadLine )

            ' Check if section is found in the current line
            If LCase( strLine ) = "[" & LCase( strSection ) & "]" Then
                strLine = Trim( objIniFile.ReadLine )

                ' Parse lines until the next section is reached
                Do While Left( strLine, 1 ) <> "["
                    ' Find position of equal sign in the line
                    intEqualPos = InStr( 1, strLine, "=", 1 )
                    If intEqualPos > 0 Then
                        strLeftString = Trim( Left( strLine, intEqualPos - 1 ) )
                        ' Check if item is found in the current line
                        If LCase( strLeftString ) = LCase( strKey ) Then
                            ReadIni = Trim( Mid( strLine, intEqualPos + 1 ) )
                            ' In case the item exists but value is blank
                            If ReadIni = "" Then
                                ReadIni = " "
                            End If
                            ' Abort loop when item is found
                            Exit Do
                        End If
                    End If

                    ' Abort if the end of the INI file is reached
                    If objIniFile.AtEndOfStream Then Exit Do

                    ' Continue with next line
                    strLine = Trim( objIniFile.ReadLine )
                Loop
            Exit Do
            End If
        Loop
        objIniFile.Close
    Else
        if BoolRunSilent = False and boolIniNotify = True then 
			WScript.Echo strFilePath & " does not exist. Using script configured settings instead"
			boolIniNotify = False
		end if
        'Wscript.Quit 1
    End If
End Function

Sub KeywordSearch(strSearchText)
if dictKWordWatchList.count > 0 then
  for each strKeyWord in dictKWordWatchList
    if instr(lcase(strSearchText), lcase(strKeyWord)) > 0 then
      strTmpKeyWordWatchList = concatenateItem(strTmpKeyWordWatchList, strKeyWord, "^")
    end if
  next
end if
end sub


Sub LoadWatchlist(strListPath, dictToLoad)
if objFSO.fileexists(strListPath) then
  Set objFile = objFSO.OpenTextFile(strListPath)
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine
          if dictToLoad.exists(lcase(strData)) = False then 
			dictToLoad.add lcase(strData), ""
		end if
        on error goto 0
    end if
  loop
end if
end sub

Sub LoadCustomDict(strListPath, dictToLoad)
if objFSO.fileexists(strListPath) then
  Set objFile = objFSO.OpenTextFile(strListPath)
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine
        if instr(strData, "|") then
          strTmpArrayDDNS = split(strData, "|")
          if dictToLoad.exists(lcase(strTmpArrayDDNS(0))) = False then _
          dictToLoad.add lcase(strTmpArrayDDNS(0)), strTmpArrayDDNS(1)
        else
          if dictToLoad.exists(lcase(strData)) = False then _
          dictToLoad.add lcase(strData), ""
        end if
        on error goto 0
    end if
  loop
end if
end sub


Sub LoadTrancoList(strListPath, dictToLoad)
if objFSO.fileexists(strListPath) then
  Set objFile = objFSO.OpenTextFile(strListPath)
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine
        if instr(strData, ",") then
          strTmpArrayDDNS = split(strData, ",")
          if dictToLoad.exists(lcase(strTmpArrayDDNS(1))) = False then _
          dictToLoad.add lcase(strTmpArrayDDNS(1)), strTmpArrayDDNS(0)
        else
          if dictToLoad.exists(lcase(strData)) = False then _
          dictToLoad.add lcase(strData), ""
        end if
        on error goto 0
    end if
  loop
end if
end sub

Function DictTrackDomain(strTmpTrackDomain)
if dictCountDomains.exists(strTmpTrackDomain) = false then 
	dictCountDomains.add strTmpTrackDomain, "" 'only count domains once
	strIpDwatchLineE = MatchIpDwatchLIst(strTmpTrackDomain) 'watch list
	DictTrackDomain = False
else
  DictTrackDomain = True
end if
End Function

Function LogHashes(dictHashlist, strHashListName, strQueriedItem)
if boolLogHashes = False then exit function
if dictHashlist.Count > 0 then	
 for each listedHash in dictHashlist
	logdata strReportsPath & "\Hashes_" & strHashListName & "_" & UniqueString & ".log", strQueriedItem & "|" & listedHash, False
 next 
end if
end function


Function DBIP_GeoLocate(intIPaddr)'Returns Country Code
Dim strTmpPubDomains
'msgbox intIPaddr & "|" & Dotted2LongIP(intIPaddr)
sSQL = "select CountryCode from DB_IP where StartRange < ? and EndRange > ? limit 1" 
DBIP_GeoLocate = ReturnCountryCode(sSQL, int(Dotted2LongIP(intIPaddr)), "CountryCode", 201) 
end function


Function ReturnCountryCode(sSQL, strQueryItem, strReturnName, intType)'129 - string   201 - long
'msgbox sSQL & "|" &  strQueryItem & "|" &  strReturnName
Set Recordset = CreateObject("ADODB.Recordset")
Set cmd = Nothing
  Set cmd = createobject("ADODB.Command")
  cmd.ActiveConnection = oCNCT
   set objparameter0 = cmd.createparameter("@VarQueryItem1", intType, 1, len(strQueryItem),strQueryItem)
   set objparameter1 = cmd.createparameter("@VarQueryItem2", intType, 1, len(strQueryItem),strQueryItem)
         cmd.CommandText = sSQL
    if objparameter0 <> Empty then 
      cmd.Parameters.Append objparameter0
    end if
    if objparameter1 <> Empty then 
      cmd.Parameters.Append objparameter1
    end if	
  Recordset.Open cmd

  If not Recordset.EOF Then 
    on error resume next
    ReturnCountryCode = Recordset.fields.item(strReturnName)
    on error goto 0
  end if
    Set cmd = Nothing
    Set objparameter0 = Nothing
    Recordset.close
    Set Recordset = Nothing

End Function


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



Function UpdateIni(iniFileName, SettingToAdd, strSection)
Dim ReadWholeFile()
Dim TextToFind

LineCount = 0

TextToFind = left(SettingToAdd,instr(SettingToAdd,"="))

Set fsoUI = CreateObject("Scripting.FileSystemObject")

If fsoUI.fileexists(iniFileName) = True then   
  'Opens the file as TextStream
  Set oReadText = fsoUI.OpenTextFile(iniFileName,ForReading, False)
  do while oReadText.AtEndOfStream <> True

    LineCount = LineCount +1   
    ReDim Preserve ReadWholeFile(LineCount)
    ReadWholeFile(LineCount) = oReadText.ReadLine 

  loop
  'Closes the file
  oReadText.Close
  'msgbox linecount


  If fsoUI.fileexists(iniFileName & "2") = False Then
      'Creates a replacement text file 
      fsoUI.CreateTextFile iniFileName & "2", True
  End If

  'Opens the file as TextStream
  Set oFileWrite = fsoUI.OpenTextFile(iniFileName & "2",forwriting, False)
  TextHasBeenAdded = False
  If IsArrayEmpty(ReadWholeFile) = False then
    For x = 1 to ubound(ReadWholeFile)
      If instr (lcase(ReadWholeFile(x)),lcase(TextToFind)) = 0 then
        oFileWrite.WRITELINE ReadWholeFile(x)
      else
        oFileWrite.WriteLine SettingToAdd
        TextHasBeenAdded = true    
       

      end if
    next
    oFileWrite.Close
	  
	If TextHasBeenAdded = False then
		Set oFileWrite = fsoUI.OpenTextFile(iniFileName & "2",forwriting, False)
		For x = 1 to ubound(ReadWholeFile)
			If instr (lcase(ReadWholeFile(x)),lcase(strSection)) = 0 then
				oFileWrite.WRITELINE ReadWholeFile(x)		
			else
				oFileWrite.WRITELINE ReadWholeFile(x)
				oFileWrite.WriteLine SettingToAdd 'if "TextToFind" was never found in the file add "SettingToAdd" to the end of file
			end if
		next
		oFileWrite.Close
	end if
    If fsoUI.fileexists (iniFileName & ".old") = True then
      fsoUI.deletefile (iniFileName & ".old")
    end if
    fsoUI.movefile iniFileName, iniFileName & ".old"
    fsoUI.movefile iniFileName & "2", iniFileName
  End if    
end if

End Function


Function IsArrayEmpty(ArrayToCheck)
          on error resume next

          if 1 > UBound(ArrayToCheck) then
            if err.number = 9 then
              IsArrayEmpty = True
            end if
          else
              IsArrayEmpty = False
          end if
    on error goto 0
End Function

Function getPositiveDetections(strVTjson)
intPositiveD = 0
if boolVT_V3 = True then
		last_analysis_stats = getdata(strVTjson, "}", chr(34) & "last_analysis_stats" & chr(34) & ": ")
  intPositiveD = getdata(last_analysis_stats, ",", chr(34) & "malicious" & chr(34) & ": ")
else 'v2 code
  intPositiveD = getdata(strVTjson, ",", chr(34) & "positives" & chr(34) & ": ")
end If
getPositiveDetections = intPositiveD
end Function


Sub SetDateFirstSeen(strDateCompare)
'msgbox strDateCompare & vbcr & isdate(strDFSlineE) & isdate(ReformatDateTime(strDateCompare, "DateFirstSeen"))
if len(strDateCompare) > 7 then
  strDateCompare = ReformatDateTime(strDateCompare, "DateFirstSeen")
end if
if isdate(strDFSlineE) = false then
  if isdate(strDateCompare) = True then
    'msgbox "..strDFSlineE = " & strDateCompare
    strDFSlineE = strDateCompare
  end if
else
  if isdate(strDateCompare) = True then
    'msgbox strDateCompare & ", " & strDFSlineE & vbcrlf & DateDiff("s", strDateCompare, strDFSlineE)
    If DateDiff("s", strDateCompare, strDFSlineE) > 0 Then 'see which date is the oldest and go with that
      'msgbox "strDFSlineE = " & strDateCompare
      strDFSlineE = strDateCompare
    End If
  end if
end if
end sub


Function ReformatDateTime(strDTtoProcess, strTimeSource)
if instr(strDTtoProcess, chr(34)) > 1 then
	strDTtoProcess = left(strDTtoProcess, instr(strDTtoProcess, chr(34)) -1)
  end if
  if left(strDTtoProcess, 1) = " " and replace(strDTtoProcess, " ", "") <> "" then
    do while left(strDTtoProcess, 1) = " "
      strDTtoProcess = right(strDTtoProcess, len(strDTtoProcess) -1)
    loop
  end if
  	if right(strDTtoProcess, 2)  = "\r" then
		strDTtoProcess = left(strDTtoProcess, len(strDTtoProcess) - 2)
	end if
  if right(strDTtoProcess,1) = "Z" then 'VirusTotal formated time
    strDTtoProcess = replace(strDTtoProcess,"-T", " ")
    strDTtoProcess = replace(strDTtoProcess,"T", " ")
    strDTtoProcess = left(strDTtoProcess, len(strDTtoProcess) -4)
    on error resume next
    if right(strDTtoProcess, 1) = "." then strDTtoProcess = left(strDTtoProcess, len(strDTtoProcess)-1)
    'if left(right(strDTtoProcess, 3), 1) = ":" then
    '  if left(right(strDTtoProcess, 7), 2) = "- " then 'fix 2010-02-01- 15:37 (2010-02-01-T15:37:29Z)
    '    strDTtoProcess = left(strDTtoProcess, len(strDTtoProcess)-7) & right(strDTtoProcess, 6)
    '  end if
    'end if
    strDTtoProcess =  FormatDateTime(strDTtoProcess)

    if err.number <> 0 then 
      objShellComplete.popup "FormatDateTime error: " & strDTtoProcess, 20
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " " & strTimeSource & " FormatDateTime error: " & strDTtoProcess & strTmpWCO_CClineE ,False 
    end if
    on error goto 0
  end if
  
  ReformatDateTime = strDTtoProcess
end Function



sub AddSLDtoDict
dictSLD.add "co",0
dictSLD.add "com",0
dictSLD.add "net",0
dictSLD.add "org",0
dictSLD.add "edu",0
dictSLD.add "gov",0
dictSLD.add "asn",0
dictSLD.add "id",0
dictSLD.add "csiro",0
End sub


Sub LoadSecondDNS()'load list from http://george.surbl.org/two-level-tlds
if objFSO.fileexists(strTLDPath & "\two-level-tlds.txt") then
  Set objFile = objFSO.OpenTextFile(strTLDPath & "\two-level-tlds.txt")
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        on error goto 0
          SecondLevelDict.add strData, 1
    end if
  loop
end if
SecondLevelDict.add "surbl.org", 1 'needed to run test.surbl.org
end sub



Sub LoadAllTLD() 'loads list from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
if objFSO.fileexists(strTLDPath & "\tld.txt") then
  Set objFile = objFSO.OpenTextFile(strTLDPath & "\tld.txt")
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        on error goto 0
          dictAllTLD.add strData, 1
    end if
  loop
end if
end sub

Sub LoadThirdDNS() 'loads list from http://www.surbl.org/static/three-level-tlds
if objFSO.fileexists(strTLDPath & "\three-level-tlds.txt") then
  Set objFile = objFSO.OpenTextFile(strTLDPath & "\three-level-tlds.txt")
  Do While Not objFile.AtEndOfStream
    if not objFile.AtEndOfStream then 'read file
        On Error Resume Next
        strData = objFile.ReadLine 
        on error goto 0
          ThirdLevelDict.add strData, 1
    end if
  loop
end if
end sub

Function invalidChars(strDomainTest)
DIm BoolReturnValue: BoolReturnValue = False
  if instr(strDomainTest, "/") > 0 then BoolReturnValue = True

invalidChars = BoolReturnValue
end function


Function LevelUp(strDomainAllLevels)
intDomainDepth = 1 'grab top two domains
stroutDomain = ""
if instr(strDomainAllLevels, ".") > 0 and isIPaddress(strDomainAllLevels) = False then 'has dot and is not IP address
  arrayLevelDomain = split(strDomainAllLevels, ".")
  if dictTLD.exists("." & arrayLevelDomain(ubound(arrayLevelDomain))) then 'Country Code TLD
    if dictSLD.exists(arrayLevelDomain(ubound(arrayLevelDomain) -1)) then 'check second level domain
      intDomainDepth = intDomainDepth + 1 'grab top 3 domains
    end if
  end if
  boolInvalid = invalidChars(strDomainAllLevels)
  for x = ubound(arrayLevelDomain) to (ubound(arrayLevelDomain) - intDomainDepth) step -1
    boolNext = False
    if stroutDomain = "" then
      stroutDomain = arrayLevelDomain(x)   
      if dictAllTLD.exists(stroutDomain) = false then
        boolInvalid = True
        exit for
      end if
      boolNext = True
    end if
    if ubound(arrayLevelDomain) > 2 and boolNext = false then
      if ThirdLevelDict.exists(arrayLevelDomain(x - 1) & "." & arrayLevelDomain(x) & "." & stroutDomain) then 'known third level domain
        stroutDomain = arrayLevelDomain(x - 2) & "." & arrayLevelDomain(x - 1) & "."  & arrayLevelDomain(x) & "." & stroutDomain
        'msgbox "four level: " & stroutDomain
        exit for 'confirmed 4 level domain     
      end if
    end if
    if ubound(arrayLevelDomain) > 1 and boolNext = false then
      if SecondLevelDict.exists(arrayLevelDomain(x) & "." & stroutDomain) then 'known second level domain
        stroutDomain = arrayLevelDomain(x - 1) & "." & arrayLevelDomain(x) & "." & stroutDomain
        'msgbox "third level: " & stroutDomain
        exit for 'confirmed 3 level domain
      end if
    end if
    if boolNext = false then
      stroutDomain = arrayLevelDomain(x) & "." & stroutDomain
    end if
  next
else 'not domain 
  stroutDomain = strDomainAllLevels
end if

LevelUp = stroutDomain
end function



Sub whoIsPopulate(strTmpWhoIs)
	  
      if strTmpRequestResponse = "|" then strTmpRequestResponse = ""
      'if VirusTotal does not have owner information get data from WhoIs lookup
      if BoolWhoisDebug = True then msgbox "Country code = " & strTmpCClineE
      if (strTmpRequestResponse = "" or BoolForceWhoisLocationLookup = True and strTmpCClineE = "|") and isIPaddress(strTmpWhoIs) = False then
        if strTmpRequestResponse = "" then 
          if boolWhoisCache = True then strTmpRequestResponse = WhoisCacheLookup(strTmpWhoIs)
        else' don't overwrite strTmpRequestResponse but populate country code and other missing data
          if boolWhoisCache = True then WhoisCacheLookup strTmpWhoIs
        end if  
        if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after cache query: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRequestResponse =" & strTmpRequestResponse, false
        if BoolWhoisDebug = True then msgbox "strTmpRequestResponse=" & strTmpRequestResponse & vbcrlf & "len=" & len(strTmpRequestResponse) & vbcrlf & "null=" & isnull(strTmpRequestResponse)
        
		if boolDisableAlienVaultWhoIs = False Then
			strAlienWho = pullAlienVault("https://otx.alienvault.com/api/v1/indicators/domain/", strTmpWhoIs, "/whois")
			if strTmpRequestResponse = "" or strTmpRequestResponse = "|" or isnull(strTmpRequestResponse) = True then 
				'msgbox "Setting with Alien"
				strTmpRequestResponse = AlienVaultWhois(strAlienWho)
			elseif strTmpWCO_CClineE = "" or strTmpCClineE = "|" then 
				'msgbox "Lookup with Alien"
				AlienVaultWhois strAlienWho
			else
				'msgbox "Leaving with Alien"
			end if
		end if
		if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after AlienVault query: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRequestResponse =" & strTmpRequestResponse, false
        
		if strTmpRequestResponse = "" or strTmpRequestResponse = "|" or isnull(strTmpRequestResponse) = True then 
          if boolEnableWhoAPI = True then strTmpRequestResponse = CheckWhoAPI(strWhoAPIRUL, strTmpWhoIs)
		  if BoolEnableDomainAPI = True then strTmpRequestResponse = CheckWhoAPI(strDomainAPIURL, strTmpWhoIs)
          if BoolWhoisDebug = True then msgbox "WhoAPI return = " & strTmpRequestResponse
        elseif strTmpWCO_CClineE = "" then ' don't overwrite strTmpRequestResponse but populate country code and other missing data
          if boolEnableWhoAPI = True then CheckWhoAPI strWhoAPIRUL, strTmpWhoIs
		  if BoolEnableDomainAPI = True then CheckWhoAPI strDomainAPIURL, strTmpWhoIs
        end if
        if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after WhoAPI: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRequestResponse =" & strTmpRequestResponse, false
        if BoolWhoisDebug = True then msgbox "second domain return:" & strTmpRequestResponse
        if strTmpRequestResponse = "" or isnull(strTmpRequestResponse) = True then  
          if sysinternalsWhois = True then strTmpRequestResponse = WhoIsDomain_Lookup(strTmpWhoIs)
        elseif strTmpCClineE = "|" or strTmpWCO_CClineE = "|" then ' don't overwrite strTmpRequestResponse but populate country code and other missing data
          if sysinternalsWhois = True then WhoIsDomain_Lookup strTmpWhoIs
        end if
        if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after whois: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE & "^" & "strTmpRequestResponse =" & strTmpRequestResponse, false
        if BoolWhoisDebug = True then msgbox "final domain return:" & strTmpRequestResponse
      elseif strTmpRequestResponse = "" then
        strTmpRequestResponse = GetIPContact(strTmpWhoIs) 'arin/ripe lookups
      end if
      strTmpRequestResponse = CleanupWhoisData(strTmpRequestResponse)
      
      if strTmpWCO_CClineE <> "|" and isIPaddress(strTmpWhoIs) = False and boolWhoisCache = True then
        CacheWhois strTmpWhoIs, strTmpRequestResponse
        if BoolWhoisDebug = True then msgbox "Cached domain whois:" & strTmpWhoIs & "=" & strTmpRequestResponse
      end if
      'set spreadsheet contact string
      if strTmpRequestResponse <> "" then 
         if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "set spreadsheet contact string: " & strTmpSSreturn & " - " & strTmpRequestResponse, false
        strTmpIPContactLineE = "|" & strTmpRequestResponse
      else
        strTmpIPContactLineE = "|"
         if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", strTmpSSreturn & " - " & "strTmpRequestResponse is null", false
      end if
      if BoolWhoisDebug = True then msgbox "whois contact line=" & strTmpIPContactLineE

End Sub

'----Seclytics functions and subs
Function dict2List(DictList, strJoin)
listReturn = ""
for each item in DictList
  listReturn = AppendValuesList(listReturn, Item , strJoin)
next
dict2List = listReturn
End function


Function getSeclyticFileCount(httpbody)
accessed_by_files = GetData(httpbody, "]", chr(34) & "accessed_by_files" & Chr(34) & ": [")
If InStr(accessed_by_files, ",") > 0 Then
	arraySeclytFiles = Split(accessed_by_files, ",")
	getSeclyticFileCount = UBound(arraySeclytFiles) + 1
Else
	getSeclyticFileCount = 0
End If
End Function


Sub SeclyticsProcess(httpbody)
SeclytFileCount = 0
SeclytFileRep = ""
SeclytRepReason = ""
DicFile_Context.RemoveAll
DicIP_Context.RemoveAll
arraycontextLists = split(httpbody,chr(34) & "type" & chr(34) & ": " )

for each contextEntry in arraycontextLists

	contextent = GetData(contextEntry, chr(34) & "id" & chr(34) & ": "  , chr(34) & "context" & chr(34) & ": {")
	'msgbox contextent
	endOfCategories = InStr(contextent, chr(34) & "country" & chr(34) & ": {")
	If endOfCategories > 0 Then
		contextent = Left(contextent, endOfCategories)
	End If
	
	cEntArrayLevel1 = split(contextent, "},")
	for each cItemLevel1 in cEntArrayLevel1
	
		contextEntArray = split(cItemLevel1, "],")
	
		for each contextItem in contextEntArray
		
		itemEntry = GetData(contextItem, "],", chr(34) & ": [")
		
		If InStr(contextEntry, chr(34) & "md5" & Chr(34)) > 0 Then 'file
			'place holder for tracking sandbox results
	
			
			If InStr(itemEntry, Chr(34)) Then 
				getJsonItems itemEntry, DicFile_Context
			End if
		Else
			'msgbox itemEntry
			If InStr(itemEntry, Chr(34)) Then 
				getJsonItems itemEntry, DicIP_Context
			End if	
		End If
		next
	
	Next
Next
End sub


Sub getJsonItems(jsonEntry,dictRecord)
if instr(jsonEntry, ",") then
  itemEntArray = split(jsonEntry, ",")
  for each entItem in itemEntArray
    tmpItem = getdata(entItem, chr(34), chr(34))
    'msgbox tmpItem
    SeclytDictAdd dictRecord, tmpItem
  next
else
    tmpItem = getdata(jsonEntry, chr(34), chr(34))
    'msgbox tmpItem
    SeclytDictAdd dictRecord, tmpItem
end if
end sub

Sub SeclytDictAdd(dictRecord, dictEntry)
If InStr(dictEntry, "|") > 0 Then dictEntry = Replace(dictEntry, "|", "^")

If isIPaddress(dictEntry) = True Then
	strIpDwatchLineE = MatchIpDwatchLIst(dictEntry)
	If boolLogIPs = True Then  logdata strReportsPath & "\IPs_Seclytic" & "_" & UniqueString & ".log", strData & "|" & dictEntry, False 'Output IP addresses associated with the lookup items.
ElseIf IsHash(dictEntry) = True Then
	If boolLogHashes = True Then logdata strReportsPath & "\Hashes_Seclytic" & "_" & UniqueString & ".log", strData & "|" & dictEntry, False
ElseIf InStr(dictEntry, "@")> 0 Then 'email address
	'not collecting email addresses
ElseIf InStr(dictEntry, "http") > 0  Then
	strURLWatchLineE = MatchURLwatchList(strURLWatchLineE, dictEntry)
	If boolLogURLs = True Then logdata strReportsPath & "\URLs_Seclytic" & "_" & UniqueString & ".log", strData & "|" & dictEntry, false
ElseIf InStr(dictEntry, vblf) > 0 Then
	'MsgBox dictEntry
ElseIf Len(dictEntry) < 32 And Right(dictEntry,3) <> "_at" And dictEntry <> "duration" Then
	if dictRecord.exists(dictEntry) = false then dictRecord.add dictEntry, ""
	DetectNameWatchlist dictEntry 'check against detection name watchlist and populate strDnameWatchLineE
	If InStr(dictEntry, ".") > 0 and InStr(dictEntry, " ") = 0  Then 'possible domain name
		strIpDwatchLineE = MatchIpDwatchLIst(dictEntry)
	End if	
ElseIf InStr(dictEntry, ".") > 0 and InStr(dictEntry, " ") = 0  Then 'possible domain name
	strIpDwatchLineE = MatchIpDwatchLIst(dictEntry)
End if	
End Sub

Function HTTPget(strRequestURL, strCheckItem, strSection, strAPIheader, strApiKey, boolHeader)
'returns HTTP body
  
  if instr(strRequestURL,"/domain/") > 0 then
    StrValidDomainName = RemoveInvalidFromDomain(strCheckItem)
  else
    StrValidDomainName = strCheckItem
  end if
  Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")

      strAVEurl = strRequestURL & StrValidDomainName &  strSection
    if boolHeader = True then 
      objHTTP.setRequestHeader strAPIheader, strApiKey 
    elseif strApiKey <> "" and strAPIheader <> "" then
      strAVEurl = strAVEurl & strAPIheader & "=" & strApiKey
    end if
   
    'objHTTP.setRequestHeader 
    objHTTP.open "GET", strAVEurl
   
  on error resume next
    objHTTP.send 
    if err.number <> 0 then
      logdata CurrentDirectory & "\VTTL_Error.log", Date & " " & Time & " " & strAPIheader  & "lookup failed with HTTP error while querying " & strCheckItem & " - " & err.description,False 
      exit function 
    end if
  on error goto 0  

  'if BoolDebugTrace = True then logdata strAlienVaultreportsPath & "\AlienV_" & replace(strData, ":",".") & ".txt", objHTTP.responseText & vbcrlf & vbcrlf,BoolEchoLog 
  if len(objHTTP.responseText) > 0 then
    HTTPget = objHTTP.responseText
  end if
   
  Set objHTTP = Nothing
end Function

Sub SeclytPdns(httpAPIbody)

PdnsSection = GetData(httpAPIbody, "]"  , chr(34) & "passive_dns" & chr(34) & ": [")
answer_ip = GetData(PdnsSection,  chr(34) , chr(34) & "answer_ip" & chr(34) & ": " & chr(34))
If isIPaddress(answer_ip) = True Then strTmpIPlineE = answer_ip
End Sub

Sub SeclytASN(httpAPIbody)
If ispipeorempty(strTmpIPContactLineE) then
	strTmpIPContactLineE = GetData(httpAPIbody, "},", chr(34) & "asn" & chr(34) & ": {")
	If InStr(strTmpIPContactLineE, Chr(34) & ": " & Chr(34)) > 0 Then
		strTmpIPContactLineE = GetData(strTmpIPContactLineE, Chr(34), Chr(34) & ": " & Chr(34))
	End If
End if
End Sub

Sub SeclytFileDate(httpAPIbody)
If ispipeorempty(strDateTimeLineE) Then
	globalHistorySect = GetData(httpAPIbody, "]"  , chr(34) & "global_history" & chr(34) & ": [")
	FileDate = GetData(globalHistorySect,  chr(34) , chr(34) & "start_at" & chr(34) & ": " & chr(34))
	If IsDate(Replace(FileDate, "T", " ")) = True Then strDateTimeLineE = Replace(FileDate, "T", " ")
End if	
End Sub

Sub SeclytWhitelist(httpAPIbody)
If ispipeorempty(AlienVaultValidation) = False Then Exit Sub 'already set
If instr(httpAPIbody, chr(34) & "type" & chr(34) & ": "  & chr(34) & "ip" & chr(34)) > 0 Then 'IP address
	ipSection = GetData(httpAPIbody, "{"  , chr(34) & "type" & chr(34) & ": "  & chr(34) & "ip" & chr(34))
	If InStr(ipSection, chr(34) & "whitelist" & chr(34) & ": "  & chr(34)) > 0 Then
		AlienVaultValidation = GetData(httpAPIbody, Chr(34)  , chr(34) & "whitelist" & chr(34) & ": "  & chr(34))
	End If
else 'domain
	lastSection = rGetData(httpAPIbody, "},", "}")
	If InStr(lastSection, Chr(34) & "whitelist" & Chr(34) & ":") > 0 Then 'whitelisted item
		AlienVaultValidation = "|Whitelist"
	End If
End if	
End Sub
'----End Seclytics functions and subs


Sub domainPassiveDNS(strPdnsIPaddress) 'set strRevDNS and pending items
        if strPdnsIPaddress = "" Or strPdnsIPaddress = "|" Then exit sub 'reverselookup IP address for the domain we are checking
        If strRevDNS = "|" Or strRevDNS = "" then
          subReverseDNSwithSinkhole strPdnsIPaddress, "8.8.8.8"
        end if
        if not DicScannedItems.Exists(strPdnsIPaddress) then
          if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Have not scanned IP address" ,BoolEchoLog 
          if not DicPendingItems.Exists(strPdnsIPaddress) then
            if BoolDebugTrace = True then logdata strDebugPath & "\VT_Debug" & "" & ".txt", "Adding IP address to pending items" ,BoolEchoLog 
            DicPendingItems.Add strPdnsIPaddress, DicPendingItems.Count 
            
          end if
          boolPendingItems = True
        end if
End Sub

Sub DetectNameWatchlist(strUniqueDname)
	if dictDnameWatchList.exists(strUniqueDname) then
		strDnameWatchLineE = concatenateItem(strDnameWatchLineE, strUniqueDname, "^")
	end If
End Sub

Function WhoisPopulate(strWhoisText) 'currently only used by Pulsedive but should work with whoAPI
strWhoisText = lcase(strWhoisText)

      ' set city, region, and country code for spreadsheet output
      if strTmpCITlineE = "" or strTmpCITlineE = "|" then
      strTmpCITlineE = Getdata(strWhoisText, Chr(34), "city" & Chr(34) & ":" & Chr(34))
      strTmpCITlineE = "|" & CleanupWhoisData(strTmpCITlineE)
      end if
      if strTmpRNlineE = "" or strTmpRNlineE = "|" then
      strTmpRNlineE = Getdata(strWhoisText , Chr(34), "state" & Chr(34) & ":" & Chr(34))
      strTmpRNlineE = "|" & CleanupWhoisData(strTmpRNlineE)
      end if
      if strTmpRNlineE = "" or strTmpRNlineE = "|" then
      strTmpRNlineE = Getdata(strWhoisText , Chr(34), "region" & Chr(34) & ":" & Chr(34))
      strTmpRNlineE = "|" & CleanupWhoisData(strTmpRNlineE)
      end if
      if strTmpCClineE = "" or strTmpCClineE = "|" then
      strTmpCClineE = Getdata(strWhoisText , Chr(34), "country" & Chr(34) & ":" & Chr(34))
      strTmpCClineE = "|" & CleanupWhoisData(strTmpCClineE)
      end if

      if strTmpWCO_CClineE = "" or strTmpWCO_CClineE = "|" then
        strTmpWCO_CClineE = Getdata(strWhoisText, Chr(34), "date_created" & Chr(34) & ":" & Chr(34))
        strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
      end if
      if strTmpWCO_CClineE = "" or strTmpWCO_CClineE = "|" then
        strTmpWCO_CClineE = Getdata(strWhoisText, Chr(34), "registered" & Chr(34) & ":" & Chr(34))
        strTmpWCO_CClineE = "|" & CleanupWhoisData(strTmpWCO_CClineE)
      end if
      tmpRegistrant = Getdata(strWhoisText, Chr(34), "++registrant" & Chr(34) & ":" & Chr(34))
      
      
	  if BoolDebugTrace = True then LogData strDebugPath & "\IP_SS_Contact.log", "results after WhoisPopulate but before moveSS: " & "strTmpWCO_CClineE =" & strTmpWCO_CClineE & "^" & "strTmpCClineE =" & strTmpCClineE , false

      MoveSSLocationEntries 'check if country code is listed as country name
      WhoisPopulate = tmpRegistrant
end function


sub Check_name_server(strNameServerText) 'currently only used by Pulsedive

nameServers = getData (strNameServerText, "]", "Name Server" & chr(34) & ":[")

if instr(nameServers, ",") > 0 then
  arrayNames = split(nameServers, ",")
  for each nameServer in arrayNames
    serverName = getdata(nameServer, chr(34), chr(34))
    if serverName <> "" then
      SinkholeNSCheck serverName
    end if
  next
else
  serverName = getdata(nameServer, chr(34), chr(34))
    if serverName <> "" then
      SinkholeNSCheck serverName
    end if
end if

end sub

Function truncateCell(cellContents)

			if len(cellContents) > 32460 then 'cell length limitation
        cellContents= left(cellContents, 32460) 'truncate

        sepLocation = InstrRev(cellContents, "^")
        if sepLocation > 0 then
          cellContents= left(cellContents, sepLocation) 'truncate to end at sep char
        end if
			end if

			truncateCell = cellContents
end function


sub PulsediveSslPopulate(PulsediveText)

if BoolDebugTrace = True then logdata strDebugPath & "\pulsedive" & "" & ".txt", PulsediveText ,BoolEchoLog
if instr(PulsediveText, chr(34) & "ssl" & chr(34) & ":") > 0 then
  pulsediveSSL = getdata(PulsediveText, "}", chr(34) & "ssl" & chr(34) & ":")
	if sslOrg = "" then sslOrg = getdata(pulsediveSSL, chr(34), chr(34) & "org" & chr(34) & ":" & chr(34))
  if sslSubject = "" then sslSubject = getdata(pulsediveSSL, chr(34), chr(34) & "subject" & chr(34) & ":" & chr(34))
end if        
end sub
