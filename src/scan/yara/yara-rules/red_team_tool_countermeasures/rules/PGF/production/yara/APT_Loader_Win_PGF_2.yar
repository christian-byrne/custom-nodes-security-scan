// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win_PGF_2
{
    meta:
        description = "PE rich header matches PGF backdoor"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        rev = 4
        author = "FireEye"
    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}