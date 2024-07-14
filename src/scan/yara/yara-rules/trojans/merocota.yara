rule merocota
{
	meta:
		author = "tjadanel @reonfleek"
		description = "Merocota DDoS Bot"
		date = "2017-07-17" 
		reference = "http://telussecuritylabs.com/threats/show/TSL20160316-02"
		md50 = "06f06ea5de55307e7c440f94d3c9461e"
		md51 = "a2e86c2145ee87ae7b6e99bac6516a3b"

	strings:
		$comm0 = "Jakarta Commons"
		$comm1 = "command.php"
		$comm2 = "pause"
		$pdb0 = "Projetos\\C++\\BotNet\\"
		$str0 = "vector<T> too long"
		$str1 = "8s7H62v1Wo"

	condition:
		all of them
}