rule win_kimjongrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.kimjongrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kimjongrat"
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
        $sequence_0 = { e9???????? c6840db4edffff2a e9???????? c6840db4edffff26 e9???????? c6840db4edffff5b eb6c }
            // n = 7, score = 100
            //   e9????????           |                     
            //   c6840db4edffff2a     | mov                 byte ptr [ebp + ecx - 0x124c], 0x2a
            //   e9????????           |                     
            //   c6840db4edffff26     | mov                 byte ptr [ebp + ecx - 0x124c], 0x26
            //   e9????????           |                     
            //   c6840db4edffff5b     | mov                 byte ptr [ebp + ecx - 0x124c], 0x5b
            //   eb6c                 | jmp                 0x6e

        $sequence_1 = { e8???????? 8bd8 83c414 85db 0f8508010000 33c9 894de4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c414               | add                 esp, 0x14
            //   85db                 | test                ebx, ebx
            //   0f8508010000         | jne                 0x10e
            //   33c9                 | xor                 ecx, ecx
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx

        $sequence_2 = { ff7004 8d4108 50 e8???????? 8b5508 8b4840 894a20 }
            // n = 7, score = 100
            //   ff7004               | push                dword ptr [eax + 4]
            //   8d4108               | lea                 eax, [ecx + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4840               | mov                 ecx, dword ptr [eax + 0x40]
            //   894a20               | mov                 dword ptr [edx + 0x20], ecx

        $sequence_3 = { ff7508 e8???????? 6a01 57 6a4c 56 e8???????? }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   6a01                 | push                1
            //   57                   | push                edi
            //   6a4c                 | push                0x4c
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_4 = { e9???????? 8b4c8f58 894dd0 898d60ffffff 8b55a4 b860240000 66854208 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4c8f58             | mov                 ecx, dword ptr [edi + ecx*4 + 0x58]
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   898d60ffffff         | mov                 dword ptr [ebp - 0xa0], ecx
            //   8b55a4               | mov                 edx, dword ptr [ebp - 0x5c]
            //   b860240000           | mov                 eax, 0x2460
            //   66854208             | test                word ptr [edx + 8], ax

        $sequence_5 = { c68540d0ffff00 e8???????? 83c40c ba???????? 33c9 8a02 42 }
            // n = 7, score = 100
            //   c68540d0ffff00       | mov                 byte ptr [ebp - 0x2fc0], 0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ba????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx

        $sequence_6 = { e9???????? c6840da0e8ffff77 e9???????? c6840da0e8ffff76 e9???????? c6840da0e8ffff65 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   c6840da0e8ffff77     | mov                 byte ptr [ebp + ecx - 0x1760], 0x77
            //   e9????????           |                     
            //   c6840da0e8ffff76     | mov                 byte ptr [ebp + ecx - 0x1760], 0x76
            //   e9????????           |                     
            //   c6840da0e8ffff65     | mov                 byte ptr [ebp + ecx - 0x1760], 0x65
            //   e9????????           |                     

        $sequence_7 = { ff30 e8???????? 8b450c 83c404 c70000000000 8b55f8 c645f000 }
            // n = 7, score = 100
            //   ff30                 | push                dword ptr [eax]
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83c404               | add                 esp, 4
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   c645f000             | mov                 byte ptr [ebp - 0x10], 0

        $sequence_8 = { e9???????? c6840dccf3ffff2d e9???????? c6840dccf3ffff7d e9???????? c6840dccf3ffff29 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   c6840dccf3ffff2d     | mov                 byte ptr [ebp + ecx - 0xc34], 0x2d
            //   e9????????           |                     
            //   c6840dccf3ffff7d     | mov                 byte ptr [ebp + ecx - 0xc34], 0x7d
            //   e9????????           |                     
            //   c6840dccf3ffff29     | mov                 byte ptr [ebp + ecx - 0xc34], 0x29
            //   e9????????           |                     

        $sequence_9 = { 8bf8 83c404 897dac 85ff 0f8418f3ffff b800400000 66854608 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   897dac               | mov                 dword ptr [ebp - 0x54], edi
            //   85ff                 | test                edi, edi
            //   0f8418f3ffff         | je                  0xfffff31e
            //   b800400000           | mov                 eax, 0x4000
            //   66854608             | test                word ptr [esi + 8], ax

    condition:
        7 of them and filesize < 1572864
}