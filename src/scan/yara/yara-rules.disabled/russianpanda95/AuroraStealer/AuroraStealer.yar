rule  AuroraStealer {

	meta:
		author = "RussianPanda"
		description = "Detects the Build/Group IDs if present / detects an unobfuscated AuroraStealer binary; tested on version 22.12.2022" 
		date = "2/7/2023"

	strings:
		$b1 = { 48 8D 0D ?? ?? 04 00 E8 ?? ?? EF FF }
		$go = "Go build ID"
		$machineid = "MachineGuid"
			
	condition:
		all of them

}
