rule win_darkdew_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.darkdew."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkdew"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8b55d0 c745b400000000 c745b80f000000 c645a400 83fa08 722e 8b4dbc }
            // n = 7, score = 100
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   c745b400000000       | mov                 dword ptr [ebp - 0x4c], 0
            //   c745b80f000000       | mov                 dword ptr [ebp - 0x48], 0xf
            //   c645a400             | mov                 byte ptr [ebp - 0x5c], 0
            //   83fa08               | cmp                 edx, 8
            //   722e                 | jb                  0x30
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]

        $sequence_1 = { 03c0 660f283485c0840110 baef7f0000 2bd1 }
            // n = 4, score = 100
            //   03c0                 | add                 eax, eax
            //   660f283485c0840110     | movapd    xmm6, xmmword ptr [eax*4 + 0x100184c0]
            //   baef7f0000           | mov                 edx, 0x7fef
            //   2bd1                 | sub                 edx, ecx

        $sequence_2 = { 7202 8b12 8bca c745ac00000000 33c0 c745b007000000 }
            // n = 6, score = 100
            //   7202                 | jb                  4
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   8bca                 | mov                 ecx, edx
            //   c745ac00000000       | mov                 dword ptr [ebp - 0x54], 0
            //   33c0                 | xor                 eax, eax
            //   c745b007000000       | mov                 dword ptr [ebp - 0x50], 7

        $sequence_3 = { 8d4d9c 8d45d4 c78586feffff00000000 0f434d9c ba14060000 }
            // n = 5, score = 100
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   c78586feffff00000000     | mov    dword ptr [ebp - 0x17a], 0
            //   0f434d9c             | cmovae              ecx, dword ptr [ebp - 0x64]
            //   ba14060000           | mov                 edx, 0x614

        $sequence_4 = { c645fc11 8b55cc 83fa08 7232 8b4db8 8d145502000000 8bc1 }
            // n = 7, score = 100
            //   c645fc11             | mov                 byte ptr [ebp - 4], 0x11
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   83fa08               | cmp                 edx, 8
            //   7232                 | jb                  0x34
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]
            //   8d145502000000       | lea                 edx, [edx*2 + 2]
            //   8bc1                 | mov                 eax, ecx

        $sequence_5 = { 6a00 ff15???????? cc 55 8bec 64a100000000 6aff }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   6aff                 | push                -1

        $sequence_6 = { b991000000 8dbc2470020000 8bf3 f3a5 8bf0 8dbc24b4040000 8d842480030000 }
            // n = 7, score = 100
            //   b991000000           | mov                 ecx, 0x91
            //   8dbc2470020000       | lea                 edi, [esp + 0x270]
            //   8bf3                 | mov                 esi, ebx
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bf0                 | mov                 esi, eax
            //   8dbc24b4040000       | lea                 edi, [esp + 0x4b4]
            //   8d842480030000       | lea                 eax, [esp + 0x380]

        $sequence_7 = { e8???????? 8bf8 c645fc19 8d55d4 837de810 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   c645fc19             | mov                 byte ptr [ebp - 4], 0x19
            //   8d55d4               | lea                 edx, [ebp - 0x2c]
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10

        $sequence_8 = { 85c0 0f8488000000 8b4df8 8d5823 8b55fc }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   0f8488000000         | je                  0x8e
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8d5823               | lea                 ebx, [eax + 0x23]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_9 = { 8db3d0feffff 8bce 83e210 8d7901 0f1f4000 }
            // n = 5, score = 100
            //   8db3d0feffff         | lea                 esi, [ebx - 0x130]
            //   8bce                 | mov                 ecx, esi
            //   83e210               | and                 edx, 0x10
            //   8d7901               | lea                 edi, [ecx + 1]
            //   0f1f4000             | nop                 dword ptr [eax]

    condition:
        7 of them and filesize < 279552
}