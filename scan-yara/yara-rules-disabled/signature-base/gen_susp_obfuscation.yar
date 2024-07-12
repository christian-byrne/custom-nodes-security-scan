
rule SUSP_Base64_Encoded_Hex_Encoded_Code {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects hex encoded code that has been base64 encoded"
      date = "2019-04-29"
      score = 65
      reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
      id = "2cfd278f-ff45-5e23-b552-dad688ab303b"
   strings:
      $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
      $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }

      $fp1 = "Microsoft Azure Code Signp$"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_Double_Base64_Encoded_Executable {
   meta:
      description = "Detects an executable that has been encoded with base64 twice"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
      date = "2019-10-29"
      hash1 = "1a172d92638e6fdb2858dcca7a78d4b03c424b7f14be75c2fd479f59049bc5f9"
      id = "6fb40ed3-1afc-5d5b-9373-4a8490177b20"
   strings:
      $ = "VFZwVEFRR" ascii wide
      $ = "RWcFRBUU" ascii wide
      $ = "UVnBUQVFF" ascii wide
      $ = "VFZvQUFBQ" ascii wide
      $ = "RWb0FBQU" ascii wide
      $ = "UVm9BQUFB" ascii wide
      $ = "VFZxQUFBR" ascii wide
      $ = "RWcUFBQU" ascii wide
      $ = "UVnFBQUFF" ascii wide
      $ = "VFZwUUFBS" ascii wide
      $ = "RWcFFBQU" ascii wide
      $ = "UVnBRQUFJ" ascii wide
      $ = "VFZxUUFBT" ascii wide
      $ = "RWcVFBQU" ascii wide
      $ = "UVnFRQUFN" ascii wide
   condition:
      1 of them
}

rule SUSP_Reversed_Base64_Encoded_EXE : FILE {
   meta:
      description = "Detects an base64 encoded executable with reversed characters"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-04-06"
      reference = "Internal Research"
      score = 80
      hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"
      id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"
   strings:
      $s1 = "AEAAAAEQATpVT"
      $s2 = "AAAAAAAAAAoVT"
      $s3 = "AEAAAAEAAAqVT"
      $s4 = "AEAAAAIAAQpVT"
      $s5 = "AEAAAAMAAQqVT"

      $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
      $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
      $sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii
   condition:
      filesize < 10000KB and 1 of them
}

rule SUSP_Script_Base64_Blocks_Jun20_1 {
   meta:
      description = "Detects suspicious file with base64 encoded payload in blocks"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
      date = "2020-06-05"
      score = 70
      id = "cef759a5-b02a-53e7-bf27-184eee6bc3fa"
   strings:
      $sa1 = "<script language=" ascii
      $sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }
   condition:
      all of them
}

rule SUSP_Reversed_Hacktool_Author : FILE {
   meta:
      description = "Detects a suspicious path traversal into a Windows folder"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
      date = "2020-06-10"
      score = 65
      id = "33e20d75-af07-5df2-82c3-c48aec37a947"
   strings:
      $x1 = "iwiklitneg" fullword ascii wide
      $x2 = " eetbus@ " ascii wide
   condition:
      filesize < 4000KB and
      1 of them
}

rule SUSP_Base64_Encoded_Hacktool_Dev {
   meta:
      description = "Detects a suspicious base64 encoded keyword"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1270626274826911744"
      date = "2020-06-10"
      score = 65
      id = "6dc7db4b-a614-51e4-a9a5-f869154dbbb1"
   strings:
      $ = "QGdlbnRpbGtpd2" ascii wide 
      $ = "BnZW50aWxraXdp" ascii wide 
      $ = "AZ2VudGlsa2l3a" ascii wide
      $ = "QGhhcm1qMH" ascii wide
      $ = "BoYXJtajB5" ascii wide
      $ = "AaGFybWowe" ascii wide
      $ = "IEBzdWJ0ZW" ascii wide
      $ = "BAc3VidGVl" ascii wide
      $ = "gQHN1YnRlZ" ascii wide
   condition:
      filesize < 6000KB and 1 of them
}
