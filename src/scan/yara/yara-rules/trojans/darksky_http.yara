rule darksky_http 
{
	meta:
		author = "tjadanel @reonfleek"
		date = "2018-01-29"
		description = "Darksky HTTP DDoS Bot"
		ref0 = "https://github.com/ims0rry/DarkSky-botnet"
		filetype = "exe"
		sha256_0 = "832e71e0f40e775a196452ee96bd9725d204223bb1fe9e8e21c2bd186f158d5f"
		sha256_1 = "3b03ca05c0c357fad3e054a41da75da6906164fb5a68725c7f46a43561dcc936"
		sha256_2 = "1147d0b48861302e43e0ab9f115dc70f60957c7931c45f93edbdf0159e1bc688"
	
	strings:

		$comm0 = "\", \"s5\":\""
		$comm1 = "\", \"s4\":\""
		$comm2 = "\", \"http\":\""
		$comm3 = "\", \"ram\":\""
		$comm4 = "\", \"s5\":\"0\", \"s4\":\"0\", \"http\":\"0\"}"
		$comm6 = "udp:"
		$comm7 = "speed:"
		$comm8 = "threads:"
		$comm9 = "method.http:"
		$encoded0 = "bndvbmtuVQ=="
		$encoded1 = "c3NlY29yUDQ2d29Xc0k="
		$encoded2 = "cmVWcmVTIG8wbzI="
		$encoded3 = "N24xVw=="
		$encoded4 = "MG9vMg=="
		$cleartext0 = "THTTPSend"
		$cleartext1 = "httpsend"
		$cleartext2 = "2o0o SerVer"
		$cleartext3 = "W1nX"
		$cleartext4 = "2oo0"
		$cleartext5 = "V1sta"
		$cleartext6 = "W1n7"
		$useragents0 = "2zAz"
		$useragents1 = "Mozilla/4.0 (compatible; Synapse)"

	condition:
		(uint16(0) == 0x5A4D) and (4 of ($comm*)) and ((3 of ($encode*) or (3 of ($cleartext*)))) and (any of ($useragents*))
}