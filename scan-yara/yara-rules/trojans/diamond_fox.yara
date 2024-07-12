rule diamond_fox
{
	meta:
		author = "tjadanel @reonfleek"
		date = "2017-09-20"
		description = "Diamond Fox: Malware as a Service"
		reference = "https://blog.malwarebytes.com/threat-analysis/2017/03/diamond-fox-p1/"
		reference1 = "https://blog.checkpoint.com/2017/05/10/diamondfox-modular-malware-one-stop-shop/"
		sha256_0 = "92b449d5932fd42a5040b26e2a849aea3deb04ae0c4e400e6ddf13acd12a94e3"
		sha256_1 = "68051027c5199d12fa6afd52e053bf3127429bdd65251308d1b6e26da10c6a9d"
	
	strings:
		$cfg0 = "L!NK" nocase
		$persist0 = "Policies\\System\\EnableLUA" wide
		$persist1 = "HKLM\\Software\\Microsoft\\Security Center\\UACDisableNotify" wide
		$persist2 = "\\Windows\\CurrentVersion\\" wide
		$persist3 = "\\Windows NT\\CurrentVersion\\" wide
		$persist4 = "Policies\\Explorer\\Run\\" wide
		$persist5 = "\\CurrentVersion\\RunOnce\\" wide
		$diamond0 = "70144646" wide
		$diamond1 = "coin" wide
		$diamond2 = "BitcoinDark" wide
		$diamond3 = "Asic" wide
		$diamond4 = "Prime" wide
		$diamond5 = "Electrum" wide
		$diamond6 = "Armory" wide
		$diamond7 = ".vbs" wide
		$comm0 = "&x=" wide
		$comm1 = "ping -n 4 127.0.0.1 > nul" wide
		$comm2 = "?p=" wide
		$comm3 = "&y=" wide
		$comm4 = "/gate.php" wide
		$comm5 = "select * from " wide

	condition:
		(uint16(0) == 0x5A4D) and (all of ($cfg*)) and (all of ($persist*)) and (all of ($comm*)) and (all of ($diamond*))
}
