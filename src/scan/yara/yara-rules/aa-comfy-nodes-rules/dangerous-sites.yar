rule SUSP_Websites {
	meta:
		author = "christian-byrne"
		description = "Detects the reference of suspicious sites"
		version = "0.2"
		date = "14.07.2024"


	strings:
		$site_1 = "https://paste.ee" nocase 
		$site_2 = "https://pastebin.com" nocase 
		$site_3 = "https://drive.google.com" nocase 
		$site_4 = "cdn.discordapp.com/attachments" nocase 
		$site_5 = "https://transfer.sh" nocase 
		$site_6 = "ngrok.io" nocase
		$site_7 = "https://anonfiles.com" nocase
		$site_8 = "https://mega.nz" nocase
		$site_9 = "https://gofile.io" nocase
		$site_10 = "https://ufile.io" nocase
		$site_11 = "https://filebin.net" nocase
		$site_12 = "https://dropmefiles.com" nocase
		$site_13 = "https://file.io" nocase
		$site_14 = "https://sendspace.com" nocase
		$site_15 = "https://bayfiles.com" nocase
		$site_16 = "https://wetransfer.com" nocase
		$site_17 = "https://uploadfiles.io" nocase
		$site_18 = "https://share.dmca.gripe" nocase
		$site_19 = "https://temp.sh" nocase
		$site_20 = "https://api.ipify.org" nocase
		$site_21 = "https://justpaste.it" nocase
		$site_22 = "https://ctrlv.it" nocase
		$site_23 = "https://hastebin.com" nocase
		$site_24 = "https://p.ip.fi" nocase
		$site_25 = "https://filepizza.com" nocase
		$site_26 = "https://mixdrop.co" nocase
		$site_27 = "https://rentry.co" nocase
		$site_28 = "https://toptal.com/developers/hastebin" nocase
		$site_29 = "https://0bin.net" nocase
		$site_30 = "https://firefox.send" nocase
		$site_31 = "https://we.tl" nocase
		$site_32 = "https://dfile.space" nocase
		$site_33 = "https://easyupload.io" nocase
    $site_34 = "https://0x0.st" nocase
    $site_35 = "https://controlc.com" nocase
    $site_36 = "https://rentry.co" nocase
    $site_37 = "https://ghostbin.com" nocase
    $site_38 = "https://zerobin.net" nocase
    $site_39 = "https://anonfile.com" nocase
    $site_40 = "https://bayfiles.com" nocase 
    $site_41 = "https://dropmefiles.com" nocase
    $site_42 = "https://file.io" nocase
    $site_43 = "https://filebin.net" nocase
    $site_44 = "hmdrnuks.gotdns.ch" nocase
    $site_45 = "http://hmdrnuks.gotdns.ch" nocase
    $site_46 = "hackingloading157.ddns.net" nocase

	condition:
		any of ($site_*)
}