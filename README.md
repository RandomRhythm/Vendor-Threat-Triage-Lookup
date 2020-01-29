### Vendor Threat Triage Lookup (VTTL)
##### VTTL utilizes various vendors to lookup intelligence for threat triage.

VTTL Performs lookups for file hashes, IP addresses and domain names. Results are output to a CSV file. Supported vendor lookups include the following:
* VirusTotal
* AlienVault OTX
* ThreatGRID
* Emerging Threats ET Intelligence
* Malshare
* Cb Response
* ThreatGRID
* ThreatCrowd
* ThreatIntelligenceAggregator (TIA)
* RiskIQ
* Collective Intelligence Framework (CIF)
* Seclytics
* Quad9
* ZEN RBL
* cbl.abuseat.org
* Zen DBL
* SURBL
* SORBS
* Barracuda

Additional data points:
* Reverse DNS
* Reverse IP (lookup to document sample of associated domains)
* Whois
* Website category (from web proxy vendors)
* Dynamic DNS
* Tranco List
  * Requires SQLite database (included in default.db)
* Geolocation (often provided via APIs already listed)
  * https://freegeoip.app
  * Internal IP Geolocation Database (included in default.db)
    * IP to Country Lite or IP to Country from https://db-ip.com/db/
* Registration date of domains
* Sinkhole checks

Combine hash lookups with tool output from:
* Sysinternals Sigcheck
* Sysinternals Autorunsc
* Cisco AMP for Networks
* EnCase
* CrowdStrike Falcon
* Rhythm-CB-Scripts Hash Dump (Cb Response scripts)

Additional features:
* Attempts to find the common name and type from VirusTotal detections
* Scores antimalware detections into categories
	* Malware Score
	* Generic Score	
	* PUA Score
	* HackerTool Score
	* Adjusted Malicious Score
* Cache results to SQLite and files on disk
* Whitelist known hashes
* Blacklist known hashes
* Track digital signatures (signatures need to be provided via combine input)
* Track file path/vendor combination (file paths and vendor provided via combine input)
* Exclude domain/subdomain/IP lookups
* Detection name watchlist
* URL watchlist (supports regex)
* Keyword watchlist
* IP/Domain watchlist


Tests:
* dbltest.com - spamhaus.org DBL
* test.surbl.org
* 127.0.0.2 - SORBS,	CBL abuseat,	Barrucda,	Spamhaus, ZEN RBL

