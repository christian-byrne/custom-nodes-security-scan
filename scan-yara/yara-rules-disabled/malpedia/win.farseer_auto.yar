rule win_farseer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.farseer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.farseer"
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
        $sequence_0 = { 8d4c2434 e8???????? eb10 6a06 68???????? 8d4c2438 }
            // n = 6, score = 100
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12
            //   6a06                 | push                6
            //   68????????           |                     
            //   8d4c2438             | lea                 ecx, [esp + 0x38]

        $sequence_1 = { 50 8d4c2440 51 8d542478 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   51                   | push                ecx
            //   8d542478             | lea                 edx, [esp + 0x78]

        $sequence_2 = { e8???????? 8d742414 e8???????? 53 50 83c8ff 8d742438 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d742414             | lea                 esi, [esp + 0x14]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   50                   | push                eax
            //   83c8ff               | or                  eax, 0xffffffff
            //   8d742438             | lea                 esi, [esp + 0x38]

        $sequence_3 = { 8d442434 50 e8???????? c68424c402000002 8b8424cc000000 bb10000000 399c24e0000000 }
            // n = 7, score = 100
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c68424c402000002     | mov                 byte ptr [esp + 0x2c4], 2
            //   8b8424cc000000       | mov                 eax, dword ptr [esp + 0xcc]
            //   bb10000000           | mov                 ebx, 0x10
            //   399c24e0000000       | cmp                 dword ptr [esp + 0xe0], ebx

        $sequence_4 = { 0f8c6cffffff 33ed 8d9424ac010000 68???????? 52 e8???????? 83c408 }
            // n = 7, score = 100
            //   0f8c6cffffff         | jl                  0xffffff72
            //   33ed                 | xor                 ebp, ebp
            //   8d9424ac010000       | lea                 edx, [esp + 0x1ac]
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_5 = { 33db 6aff 899c2498000000 53 8d8424a4000000 be0f000000 50 }
            // n = 7, score = 100
            //   33db                 | xor                 ebx, ebx
            //   6aff                 | push                -1
            //   899c2498000000       | mov                 dword ptr [esp + 0x98], ebx
            //   53                   | push                ebx
            //   8d8424a4000000       | lea                 eax, [esp + 0xa4]
            //   be0f000000           | mov                 esi, 0xf
            //   50                   | push                eax

        $sequence_6 = { 7510 8bc1 eb0c 0fb6c9 0fbe8940454200 03c1 40 }
            // n = 7, score = 100
            //   7510                 | jne                 0x12
            //   8bc1                 | mov                 eax, ecx
            //   eb0c                 | jmp                 0xe
            //   0fb6c9               | movzx               ecx, cl
            //   0fbe8940454200       | movsx               ecx, byte ptr [ecx + 0x424540]
            //   03c1                 | add                 eax, ecx
            //   40                   | inc                 eax

        $sequence_7 = { 83c404 83bc24e402000010 7210 8b9424d0020000 52 e8???????? 83c404 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   83bc24e402000010     | cmp                 dword ptr [esp + 0x2e4], 0x10
            //   7210                 | jb                  0x12
            //   8b9424d0020000       | mov                 edx, dword ptr [esp + 0x2d0]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 85410c 7405 e8???????? 8d742440 e8???????? 85c0 }
            // n = 6, score = 100
            //   85410c               | test                dword ptr [ecx + 0xc], eax
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8d742440             | lea                 esi, [esp + 0x40]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { e9???????? 8bc3 c1f805 8d048520634200 83e31f 8985e4efffff 8b00 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   c1f805               | sar                 eax, 5
            //   8d048520634200       | lea                 eax, [eax*4 + 0x426320]
            //   83e31f               | and                 ebx, 0x1f
            //   8985e4efffff         | mov                 dword ptr [ebp - 0x101c], eax
            //   8b00                 | mov                 eax, dword ptr [eax]

    condition:
        7 of them and filesize < 347328
}