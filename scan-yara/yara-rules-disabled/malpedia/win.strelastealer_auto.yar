rule win_strelastealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.strelastealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer"
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
        $sequence_0 = { 0f85e6030000 6804010000 8d942464010000 53 52 e8???????? }
            // n = 6, score = 100
            //   0f85e6030000         | jne                 0x3ec
            //   6804010000           | push                0x104
            //   8d942464010000       | lea                 edx, [esp + 0x164]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_1 = { ff15???????? 8b442434 8b4c2438 53 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   8b4c2438             | mov                 ecx, dword ptr [esp + 0x38]
            //   53                   | push                ebx

        $sequence_2 = { 488945f0 488d15d8a20000 b805000000 894520 }
            // n = 4, score = 100
            //   488945f0             | mov                 dword ptr [esp + 0x20], edi
            //   488d15d8a20000       | dec                 eax
            //   b805000000           | lea                 edx, [0xa1eb]
            //   894520               | dec                 eax

        $sequence_3 = { 885909 b801000000 83c404 51 0fb69220a30010 3011 33d2 }
            // n = 7, score = 100
            //   885909               | mov                 byte ptr [ecx + 9], bl
            //   b801000000           | mov                 eax, 1
            //   83c404               | add                 esp, 4
            //   51                   | push                ecx
            //   0fb69220a30010       | movzx               edx, byte ptr [edx + 0x1000a320]
            //   3011                 | xor                 byte ptr [ecx], dl
            //   33d2                 | xor                 edx, edx

        $sequence_4 = { ff15???????? 33c9 8be8 85db 7612 8bc1 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   8be8                 | mov                 ebp, eax
            //   85db                 | test                ebx, ebx
            //   7612                 | jbe                 0x14
            //   8bc1                 | mov                 eax, ecx

        $sequence_5 = { 48895c2408 4889742410 57 4c8bd2 488d351b43ffff }
            // n = 5, score = 100
            //   48895c2408           | xor                 edx, edx
            //   4889742410           | dec                 eax
            //   57                   | mov                 dword ptr [esp + 0x30], eax
            //   4c8bd2               | mov                 dword ptr [esp + 0x28], 1
            //   488d351b43ffff       | dec                 esp

        $sequence_6 = { 488d442478 33d2 4889442430 c744242801000000 4c897c2420 }
            // n = 5, score = 100
            //   488d442478           | xor                 eax, eax
            //   33d2                 | push                ebx
            //   4889442430           | dec                 eax
            //   c744242801000000     | sub                 esp, 0x20
            //   4c897c2420           | dec                 eax

        $sequence_7 = { 488d15eba10000 488d0dc4a10000 e8???????? 488d15e8a10000 488d0dd9a10000 }
            // n = 5, score = 100
            //   488d15eba10000       | lea                 eax, [0x747f]
            //   488d0dc4a10000       | dec                 eax
            //   e8????????           |                     
            //   488d15e8a10000       | mov                 ebx, ecx
            //   488d0dd9a10000       | dec                 eax

        $sequence_8 = { 0f85bc030000 8b442414 53 53 53 53 8d54244c }
            // n = 7, score = 100
            //   0f85bc030000         | jne                 0x3c2
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d54244c             | lea                 edx, [esp + 0x4c]

        $sequence_9 = { 740d 488bc8 49878cff20ac0100 eb0a 4d87b4ff20ac0100 33c0 }
            // n = 6, score = 100
            //   740d                 | dec                 eax
            //   488bc8               | mov                 dword ptr [esp + 0x28], edi
            //   49878cff20ac0100     | inc                 ebp
            //   eb0a                 | xor                 ecx, ecx
            //   4d87b4ff20ac0100     | je                  0xf
            //   33c0                 | dec                 eax

        $sequence_10 = { 4c8d05c7680100 c744243000020080 488d1548690100 48897c2428 4533c9 }
            // n = 5, score = 100
            //   4c8d05c7680100       | dec                 esp
            //   c744243000020080     | lea                 eax, [0x168c7]
            //   488d1548690100       | mov                 dword ptr [esp + 0x30], 0x80000200
            //   48897c2428           | dec                 eax
            //   4533c9               | lea                 edx, [0x16948]

        $sequence_11 = { 53 4883ec20 488d057f740000 488bd9 483bc8 7418 }
            // n = 6, score = 100
            //   53                   | mov                 ecx, eax
            //   4883ec20             | dec                 ecx
            //   488d057f740000       | xchg                dword ptr [edi + edi*8 + 0x1ac20], ecx
            //   488bd9               | jmp                 0xc
            //   483bc8               | dec                 ebp
            //   7418                 | xchg                dword ptr [edi + edi*8 + 0x1ac20], esi

        $sequence_12 = { 488d3de6070100 eb07 488d3dc5070100 4533ed }
            // n = 4, score = 100
            //   488d3de6070100       | cmp                 ecx, eax
            //   eb07                 | je                  0x1d
            //   488d3dc5070100       | dec                 eax
            //   4533ed               | lea                 eax, [esp + 0x78]

        $sequence_13 = { 51 6a00 6a00 6a1a 6a00 ff15???????? 68???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a1a                 | push                0x1a
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_14 = { 51 8d94247c040000 52 ff15???????? }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   8d94247c040000       | lea                 edx, [esp + 0x47c]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_15 = { 8b4508 ff34c580b10010 ff15???????? 5d c3 6a0c }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c580b10010       | push                dword ptr [eax*8 + 0x1000b180]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a0c                 | push                0xc

    condition:
        7 of them and filesize < 266240
}