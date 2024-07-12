rule konni
{
	meta:
		author = "tjadanel @reonfleek"
		date = "2017-07-27"
		description = "Yara signature for Konni malware DLL"
		filetype = "dll"
		reference0 = "http://blog.talosintelligence.com/2017/07/konni-references-north-korean-missile-capabilities.html"
		reference1 = "https://vallejo.cc/2017/07/08/analysis-of-new-variant-of-konni-rat/"
		sha256_0 = "290b1e2415f88fc3dd1d53db3ba90c4a760cf645526c8240af650751b1652b8a"
		sha256_1 = "74bc1ce71543f1bca355f61567bf36711a28a250a572913daa7595c15200d12a"
		sha256_2 = "8ba433593dbd82a97c47d2a843fd0123509f5d7714f478949fe2237164474039"
		sha256_3 = "2ce64720ffb559becae983ce5341f0455122a8b9e9a7f3103c208d5b13706dcb"

	strings:
		$pdb0 = "\\0_work\\planes\\"
		$pdb1 = "\\0_work\\_programe\\"
		$introspect_str0 = "System Type:"
		$introspect_str1 = "OS is :"
		$introspect_str2 = "Drive Information is as follow."
		$introspect_str3 = "This computer's username is"
		$introspect_str4 = "This computer's name is"
		$introspect_str5 = "This computer's IP Address is"
		$cnc_cmd0 = "http://%s/weget/download.php?file=%s_dropcom" ascii
		$cnc_cmd1 = "/upload.php" nocase
		$cnc_cmd2 = "/uploadtm.php" nocase
		$cnc_cmd3 = "/download.php" nocase
		$tmp_files0 = "tedsul.ocx" nocase
		$tmp_files1 = "helpsol.ocx" nocase
		$tmp_files2 = "trepsl.ocx" nocase
		$tmp_files3 = "psltred.ocx" nocase
		$tmp_files4 = "solhelp.ocx" nocase
		$tmp_files5 = "sulted.ocx" nocase
	
	condition:
		(uint16(0) == 0x5A4D) and (any of ($pdb*)) and (all of ($introspect_str*)) and (4 of ($cnc_cmd*, $tmp_files*))
}