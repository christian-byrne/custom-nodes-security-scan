// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_ADPassHunt_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
        $sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}