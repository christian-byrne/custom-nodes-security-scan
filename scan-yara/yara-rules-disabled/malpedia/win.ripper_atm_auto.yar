rule win_ripper_atm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ripper_atm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ripper_atm"
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
        $sequence_0 = { 8b7d08 2175fc 397714 7e2a ff770c 8b33 8bcb }
            // n = 7, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   2175fc               | and                 dword ptr [ebp - 4], esi
            //   397714               | cmp                 dword ptr [edi + 0x14], esi
            //   7e2a                 | jle                 0x2c
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   8b33                 | mov                 esi, dword ptr [ebx]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_1 = { 0f434dd8 837dd408 8d5598 52 8d9550ffffff 52 }
            // n = 6, score = 100
            //   0f434dd8             | cmovae              ecx, dword ptr [ebp - 0x28]
            //   837dd408             | cmp                 dword ptr [ebp - 0x2c], 8
            //   8d5598               | lea                 edx, [ebp - 0x68]
            //   52                   | push                edx
            //   8d9550ffffff         | lea                 edx, [ebp - 0xb0]
            //   52                   | push                edx

        $sequence_2 = { 3938 8b45ec 7408 8b4de8 3b4810 7327 8b4e08 }
            // n = 7, score = 100
            //   3938                 | cmp                 dword ptr [eax], edi
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   7408                 | je                  0xa
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   3b4810               | cmp                 ecx, dword ptr [eax + 0x10]
            //   7327                 | jae                 0x29
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]

        $sequence_3 = { 6a0f 50 ff15???????? 85c0 7402 32c0 c20800 }
            // n = 7, score = 100
            //   6a0f                 | push                0xf
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   32c0                 | xor                 al, al
            //   c20800               | ret                 8

        $sequence_4 = { 8b02 6a04 8b4804 03ca e8???????? }
            // n = 5, score = 100
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   6a04                 | push                4
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   03ca                 | add                 ecx, edx
            //   e8????????           |                     

        $sequence_5 = { 6a1c e8???????? 59 85c0 7420 33c9 c7400410000000 }
            // n = 7, score = 100
            //   6a1c                 | push                0x1c
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7420                 | je                  0x22
            //   33c9                 | xor                 ecx, ecx
            //   c7400410000000       | mov                 dword ptr [eax + 4], 0x10

        $sequence_6 = { c1f805 83e21f 8b0c85f0974400 c1e206 8a441124 3245fe 247f }
            // n = 7, score = 100
            //   c1f805               | sar                 eax, 5
            //   83e21f               | and                 edx, 0x1f
            //   8b0c85f0974400       | mov                 ecx, dword ptr [eax*4 + 0x4497f0]
            //   c1e206               | shl                 edx, 6
            //   8a441124             | mov                 al, byte ptr [ecx + edx + 0x24]
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   247f                 | and                 al, 0x7f

        $sequence_7 = { 51 8d55c8 8d4d8c e8???????? 83c410 84c0 7445 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d55c8               | lea                 edx, [ebp - 0x38]
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   84c0                 | test                al, al
            //   7445                 | je                  0x47

        $sequence_8 = { 8bf9 50 e8???????? ff7518 8d45ec ff7514 8bcf }
            // n = 7, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8bcf                 | mov                 ecx, edi

        $sequence_9 = { 03f0 8b442424 2bc1 99 f77c2418 47 3bf8 }
            // n = 7, score = 100
            //   03f0                 | add                 esi, eax
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   2bc1                 | sub                 eax, ecx
            //   99                   | cdq                 
            //   f77c2418             | idiv                dword ptr [esp + 0x18]
            //   47                   | inc                 edi
            //   3bf8                 | cmp                 edi, eax

    condition:
        7 of them and filesize < 724992
}