rule win_kurton_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.kurton."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kurton"
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
        $sequence_0 = { 89542430 8d8c24b8000000 89542434 50 8954243c }
            // n = 5, score = 100
            //   89542430             | mov                 dword ptr [esp + 0x30], edx
            //   8d8c24b8000000       | lea                 ecx, [esp + 0xb8]
            //   89542434             | mov                 dword ptr [esp + 0x34], edx
            //   50                   | push                eax
            //   8954243c             | mov                 dword ptr [esp + 0x3c], edx

        $sequence_1 = { 83c8ff eb1f 8bce 83e61f c1f905 8bc6 8b0c8da05b0210 }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb1f                 | jmp                 0x21
            //   8bce                 | mov                 ecx, esi
            //   83e61f               | and                 esi, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8bc6                 | mov                 eax, esi
            //   8b0c8da05b0210       | mov                 ecx, dword ptr [ecx*4 + 0x10025ba0]

        $sequence_2 = { 33c0 8dbc2458010000 c744242800010000 f3ab 8d442428 8d8c2458010000 50 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8dbc2458010000       | lea                 edi, [esp + 0x158]
            //   c744242800010000     | mov                 dword ptr [esp + 0x28], 0x100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   8d8c2458010000       | lea                 ecx, [esp + 0x158]
            //   50                   | push                eax

        $sequence_3 = { 889c2478040200 e8???????? 89b42474040200 e9???????? b91f000000 }
            // n = 5, score = 100
            //   889c2478040200       | mov                 byte ptr [esp + 0x20478], bl
            //   e8????????           |                     
            //   89b42474040200       | mov                 dword ptr [esp + 0x20474], esi
            //   e9????????           |                     
            //   b91f000000           | mov                 ecx, 0x1f

        $sequence_4 = { 64a100000000 50 64892500000000 81ecb8000000 8a442403 53 }
            // n = 6, score = 100
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   81ecb8000000         | sub                 esp, 0xb8
            //   8a442403             | mov                 al, byte ptr [esp + 3]
            //   53                   | push                ebx

        $sequence_5 = { 84c0 752b 8b442414 3bc3 }
            // n = 4, score = 100
            //   84c0                 | test                al, al
            //   752b                 | jne                 0x2d
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   3bc3                 | cmp                 eax, ebx

        $sequence_6 = { 8d88740a0000 8988280b0000 33c9 c780180b0000902f0210 }
            // n = 4, score = 100
            //   8d88740a0000         | lea                 ecx, [eax + 0xa74]
            //   8988280b0000         | mov                 dword ptr [eax + 0xb28], ecx
            //   33c9                 | xor                 ecx, ecx
            //   c780180b0000902f0210     | mov    dword ptr [eax + 0xb18], 0x10022f90

        $sequence_7 = { 83c410 c20400 68???????? e8???????? 6a00 6a00 6a01 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   c20400               | ret                 4
            //   68????????           |                     
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_8 = { b91f000000 33c0 8dbc24ad000000 889c24ac000000 f3ab 66ab }
            // n = 6, score = 100
            //   b91f000000           | mov                 ecx, 0x1f
            //   33c0                 | xor                 eax, eax
            //   8dbc24ad000000       | lea                 edi, [esp + 0xad]
            //   889c24ac000000       | mov                 byte ptr [esp + 0xac], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax

        $sequence_9 = { 895de0 895ddc 895dfc 897de4 740a 803800 7405 }
            // n = 7, score = 100
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi
            //   740a                 | je                  0xc
            //   803800               | cmp                 byte ptr [eax], 0
            //   7405                 | je                  7

    condition:
        7 of them and filesize < 344064
}