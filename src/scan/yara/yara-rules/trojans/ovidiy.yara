rule ovidiy
{
	meta:
		author = "tjadanel @reonfleek"
		date = "2017-09-06"
		description = "Ovidiy Stealer: Russian credential theft malware"
		reference = "https://www.proofpoint.com/us/threat-insight/post/meet-ovidiy-stealer-bringing-credential-theft-masses"
		sha256_0 = "ef29fef8de847585d6e54d88a3288996b77ae15cb39db3129441be70a7b296ab"
		sha256_0 = "c59644c0c879382ce5324d9a5ac2c6cb57762979b9bbdf592c39544a3fec2222"
		sha256_0 = "3ddc17470fb86dcb4b16705eb78bcbcb24dce70545f512ce75c4a0747474ef52"
	
	strings:
		$ovidiy0 = "ovidiy" nocase
		$ovidiy1 = "Ovidiy.exe" ascii
		$dotnet0 = "System.Net" ascii
		$dotnet1 = "AssemblyFileVersionAttribute" ascii
		$dotnet2 = "System.IO" ascii
		$dotnet3 = "GuidAttribute" ascii
		$dotnet4 = "System.Runtime.CompilerServices" ascii
		$dotnet5 = "CRYPT32.dlL" ascii
		$obfuscator0 = "ConfuserEx v" ascii
		$obfuscator1 = "Ovidiy.g.resources" ascii
		$obfuscator2 = "<Module>" ascii
		$plaintext0 = "get_Login"
		$plaintext1 = "set_Login"
		$plaintext2 = "get_Password"
		$plaintext3 = "set_Password"
		$plaintext4 = "get_SimpleUid"

	condition:
		(uint16(0) == 0x5A4D) and (4 of ($dotnet*)) and (all of ($ovidiy*)) and ((2 of ($obfuscator*) or (all of ($plaintext*))))
}