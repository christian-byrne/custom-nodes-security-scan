// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Builder_MSIL_SinfulOffice_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SinfulOffice' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "9940e18f-e3c7-450f-801a-07dd534ccb9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}