rule win_unidentified_031_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_031."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_031"
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
        $sequence_0 = { 0f84a6010000 3bfd 0f849e010000 50 e8???????? 6a00 6a01 }
            // n = 7, score = 100
            //   0f84a6010000         | je                  0x1ac
            //   3bfd                 | cmp                 edi, ebp
            //   0f849e010000         | je                  0x1a4
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_1 = { 891f 8dbe9c000000 8b07 3bc3 7411 50 53 }
            // n = 7, score = 100
            //   891f                 | mov                 dword ptr [edi], ebx
            //   8dbe9c000000         | lea                 edi, [esi + 0x9c]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   3bc3                 | cmp                 eax, ebx
            //   7411                 | je                  0x13
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_2 = { ffd6 8d4dc8 ffd6 8d4db0 ffd6 8d4d9c ffd6 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   ffd6                 | call                esi
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   ffd6                 | call                esi
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   ffd6                 | call                esi

        $sequence_3 = { c78504fdffff08800000 c7853cfeffff15000000 c78534feffff02000000 ff15???????? c785ecfcffff3c624000 c785e4fcffff08800000 c785fcfdffff18000000 }
            // n = 7, score = 100
            //   c78504fdffff08800000     | mov    dword ptr [ebp - 0x2fc], 0x8008
            //   c7853cfeffff15000000     | mov    dword ptr [ebp - 0x1c4], 0x15
            //   c78534feffff02000000     | mov    dword ptr [ebp - 0x1cc], 2
            //   ff15????????         |                     
            //   c785ecfcffff3c624000     | mov    dword ptr [ebp - 0x314], 0x40623c
            //   c785e4fcffff08800000     | mov    dword ptr [ebp - 0x31c], 0x8008
            //   c785fcfdffff18000000     | mov    dword ptr [ebp - 0x204], 0x18

        $sequence_4 = { e8???????? 8945a0 8d7cbdd0 ff37 50 8bce e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8945a0               | mov                 dword ptr [ebp - 0x60], eax
            //   8d7cbdd0             | lea                 edi, [ebp + edi*4 - 0x30]
            //   ff37                 | push                dword ptr [edi]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_5 = { 895508 0f8203ffffff 83c8ff 5f 5e 5b 5d }
            // n = 7, score = 100
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   0f8203ffffff         | jb                  0xffffff09
            //   83c8ff               | or                  eax, 0xffffffff
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp

        $sequence_6 = { 51 52 e8???????? 8d9564ffffff 8d4dc8 89856cffffff }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d9564ffffff         | lea                 edx, [ebp - 0x9c]
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   89856cffffff         | mov                 dword ptr [ebp - 0x94], eax

        $sequence_7 = { 57 50 e8???????? 3bc3 740e 895e7c 3dc3040000 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   740e                 | je                  0x10
            //   895e7c               | mov                 dword ptr [esi + 0x7c], ebx
            //   3dc3040000           | cmp                 eax, 0x4c3

        $sequence_8 = { 8b3f eb03 8b7de0 c7467c01000000 8b4668 ff75e8 57 }
            // n = 7, score = 100
            //   8b3f                 | mov                 edi, dword ptr [edi]
            //   eb03                 | jmp                 5
            //   8b7de0               | mov                 edi, dword ptr [ebp - 0x20]
            //   c7467c01000000       | mov                 dword ptr [esi + 0x7c], 1
            //   8b4668               | mov                 eax, dword ptr [esi + 0x68]
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   57                   | push                edi

        $sequence_9 = { 68???????? 85c0 0f9fc3 f7db ff15???????? 0fbfc0 8b55cc }
            // n = 7, score = 100
            //   68????????           |                     
            //   85c0                 | test                eax, eax
            //   0f9fc3               | setg                bl
            //   f7db                 | neg                 ebx
            //   ff15????????         |                     
            //   0fbfc0               | movsx               eax, ax
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]

    condition:
        7 of them and filesize < 1998848
}