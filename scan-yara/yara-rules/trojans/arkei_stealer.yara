rule arkei_stealer
{
	meta:
		author = "tjadanel @reonfleek"
		date = "2017-06-13"
		description = "Yara signature for Arkei Stealer"
		filetype = "exe"
		reference0 = "https://twitter.com/4chr4f2/status/969764259222597633"
		sha256_0 = "9cb0c0b8ae1664606d176100ffafa9904fe58e68c6e4e50b134da13a41c82b19"
		sha256_1 = "ecbd4594c700589b3e3f6cd808e75fba924c8568e1e48d80b707fe64a5a6ec73"
		sha256_2 = "1192fd0a98448949022d4d4d840d20670b0eac014cbb8eaadfecb0155c9fc187"

	strings:
        $a1 = "Arkei" fullword
        $s2 = "ip-api.com" fullword
        $s3 = "TRUE" fullword
        $s4 = "FALSE" fullword
        $s5 = "1830365600" fullword
        $s6 = "wallet.dat" fullword
        $s7 = "credit_cards" fullword
        $s8 = "/server/checkingLicense" fullword
        $s9 = "/server/gate" fullword
        $s10 = "/server/getter" fullword
        $s11 = "/server/grubConfig" fullword

    condition:
        $a1  and (5 of ($s*))
}