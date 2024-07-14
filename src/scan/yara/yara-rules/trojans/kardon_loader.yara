rule kardon_loader
{
	meta:
		author = "tjnel @reonfleek"
		date = "2017-06-10"
		description = "Yara signature for Kardon Loader"
		filetype = "exe"
		reference0 = "https://asert.arbornetworks.com/kardon-loader-looks-for-beta-testers/"
		sha256_0 = "fd0dfb173aff74429c6fed55608ee99a24e28f64ae600945e15bf5fce6406aee"
		sha256_1 = "3c64d7dbef4b7e0dd81a5076172451334fe9669800c40c895567226f7cb7cdc7"
		sha256_2 = "fd0dfb173aff74429c6fed55608ee99a24e28f64ae600945e15bf5fce6406aee"
	
	strings:
		$c0 = "&op=%d&td=%s" ascii
		$c1 = "uni=1" ascii
		$c2 = "id=%s&os=%s&pv=%s&ip=%s&cn=%s&un=%s&ca=%s" fullword ascii
		$a0 = "KVMKVMKVM" fullword ascii
		$a1 = "VMwareVMware" fullword ascii
		$a2 = "VBoxVBoxVBox" fullword ascii
		$a3 = "avghook" ascii
		$a4 = "sbiedll.dll" fullword ascii
		$s0 = "\\Documents\\Programming\\KRDN\\CLIENT" ascii
		$s1 = "POST %s HTTP/1.1" fullword ascii
		$s2 = "/gate.php" ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
		$s4 = "notask" fullword ascii
		$s5 = "%s\\%s.exe" fullword ascii
		$s6 = ".rdata$zzzdbg" fullword ascii

	condition:
			( uint16(0) == 0x5a4d and
			(any of ($c*)) and 
			(all of ($a*)) and 
			(3 of ($s*)))
}
