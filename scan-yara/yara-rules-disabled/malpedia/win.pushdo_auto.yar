rule win_pushdo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.pushdo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pushdo"
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
        $sequence_0 = { 50 ff15???????? 33d2 b9ffff0000 }
            // n = 4, score = 1300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33d2                 | xor                 edx, edx
            //   b9ffff0000           | mov                 ecx, 0xffff

        $sequence_1 = { f7f9 33c9 ba88020000 f7e2 0f90c1 }
            // n = 5, score = 1300
            //   f7f9                 | idiv                ecx
            //   33c9                 | xor                 ecx, ecx
            //   ba88020000           | mov                 edx, 0x288
            //   f7e2                 | mul                 edx
            //   0f90c1               | seto                cl

        $sequence_2 = { 8b45fc b10b d3c0 61 }
            // n = 4, score = 1200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   b10b                 | mov                 cl, 0xb
            //   d3c0                 | rol                 eax, cl
            //   61                   | popal               

        $sequence_3 = { 81ec18010000 6800010000 6a00 8d85f0feffff }
            // n = 4, score = 800
            //   81ec18010000         | sub                 esp, 0x118
            //   6800010000           | push                0x100
            //   6a00                 | push                0
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]

        $sequence_4 = { 736a 8b45fc 0fbe8c05f0feffff 038de8feffff 8b45fc }
            // n = 5, score = 800
            //   736a                 | jae                 0x6c
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fbe8c05f0feffff     | movsx               ecx, byte ptr [ebp + eax - 0x110]
            //   038de8feffff         | add                 ecx, dword ptr [ebp - 0x118]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { 0fbe1410 03ca 81e1ff000000 898de8feffff 8b85e8feffff 8a8c05f0feffff }
            // n = 6, score = 800
            //   0fbe1410             | movsx               edx, byte ptr [eax + edx]
            //   03ca                 | add                 ecx, edx
            //   81e1ff000000         | and                 ecx, 0xff
            //   898de8feffff         | mov                 dword ptr [ebp - 0x118], ecx
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   8a8c05f0feffff       | mov                 cl, byte ptr [ebp + eax - 0x110]

        $sequence_6 = { c785e8feffff00000000 c745f400000000 c745fc00000000 eb09 8b55fc 83c201 8955fc }
            // n = 7, score = 800
            //   c785e8feffff00000000     | mov    dword ptr [ebp - 0x118], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c201               | add                 edx, 1
            //   8955fc               | mov                 dword ptr [ebp - 4], edx

        $sequence_7 = { 33d1 8b450c 0345fc 8810 e9???????? }
            // n = 5, score = 800
            //   33d1                 | xor                 edx, ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   8810                 | mov                 byte ptr [eax], dl
            //   e9????????           |                     

        $sequence_8 = { e8???????? 83c41c 85c0 7503 8975fc }
            // n = 5, score = 600
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   8975fc               | mov                 dword ptr [ebp - 4], esi

        $sequence_9 = { 53 53 894808 8b4e14 50 }
            // n = 5, score = 600
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b4e14               | mov                 ecx, dword ptr [esi + 0x14]
            //   50                   | push                eax

        $sequence_10 = { 53 6a18 ffd6 ffb5f4f7ffff 8d85f4fbffff 50 }
            // n = 6, score = 600
            //   53                   | push                ebx
            //   6a18                 | push                0x18
            //   ffd6                 | call                esi
            //   ffb5f4f7ffff         | push                dword ptr [ebp - 0x80c]
            //   8d85f4fbffff         | lea                 eax, [ebp - 0x40c]
            //   50                   | push                eax

        $sequence_11 = { 0fb6c3 6a03 33d2 5f f7f7 }
            // n = 5, score = 600
            //   0fb6c3               | movzx               eax, bl
            //   6a03                 | push                3
            //   33d2                 | xor                 edx, edx
            //   5f                   | pop                 edi
            //   f7f7                 | div                 edi

        $sequence_12 = { 8d45ec 50 8d4598 50 57 57 }
            // n = 6, score = 600
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   50                   | push                eax
            //   57                   | push                edi
            //   57                   | push                edi

        $sequence_13 = { 52 8d8588fbffff 50 e8???????? }
            // n = 4, score = 500
            //   52                   | push                edx
            //   8d8588fbffff         | lea                 eax, [ebp - 0x478]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_14 = { a1???????? 6bc00a 057f0a0000 33d2 b9a1190000 f7f1 }
            // n = 6, score = 200
            //   a1????????           |                     
            //   6bc00a               | imul                eax, eax, 0xa
            //   057f0a0000           | add                 eax, 0xa7f
            //   33d2                 | xor                 edx, edx
            //   b9a1190000           | mov                 ecx, 0x19a1
            //   f7f1                 | div                 ecx

        $sequence_15 = { e8???????? 89859cd3ffff 83bd9cd3ffff00 0f8ea0000000 8d8550d3ffff 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   89859cd3ffff         | mov                 dword ptr [ebp - 0x2c64], eax
            //   83bd9cd3ffff00       | cmp                 dword ptr [ebp - 0x2c64], 0
            //   0f8ea0000000         | jle                 0xa6
            //   8d8550d3ffff         | lea                 eax, [ebp - 0x2cb0]
            //   50                   | push                eax

        $sequence_16 = { 3b4dd8 7f28 8b55e4 3b55d8 0f85cf000000 8b45d8 }
            // n = 6, score = 200
            //   3b4dd8               | cmp                 ecx, dword ptr [ebp - 0x28]
            //   7f28                 | jg                  0x2a
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   3b55d8               | cmp                 edx, dword ptr [ebp - 0x28]
            //   0f85cf000000         | jne                 0xd5
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_17 = { 81bd5cfeffff70170000 0f83e2010000 8b855cfeffff 33d2 b964000000 f7f1 85d2 }
            // n = 7, score = 200
            //   81bd5cfeffff70170000     | cmp    dword ptr [ebp - 0x1a4], 0x1770
            //   0f83e2010000         | jae                 0x1e8
            //   8b855cfeffff         | mov                 eax, dword ptr [ebp - 0x1a4]
            //   33d2                 | xor                 edx, edx
            //   b964000000           | mov                 ecx, 0x64
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx

        $sequence_18 = { ff55e4 8945c8 eb11 8b4dd4 }
            // n = 4, score = 200
            //   ff55e4               | call                dword ptr [ebp - 0x1c]
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   eb11                 | jmp                 0x13
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]

        $sequence_19 = { 83c404 c1e002 8945e4 8b4de4 }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   c1e002               | shl                 eax, 2
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_20 = { 50 8b4dfc 51 e8???????? 85c0 7c3b 8b55f0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7c3b                 | jl                  0x3d
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]

    condition:
        7 of them and filesize < 163840
}