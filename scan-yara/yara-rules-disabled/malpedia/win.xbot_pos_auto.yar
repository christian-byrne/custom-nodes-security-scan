rule win_xbot_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xbot_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xbot_pos"
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
        $sequence_0 = { 8b8d50fcffff 8d148d34935500 899558fcffff 8d8d2cfeffff e8???????? 8b8558fcffff 0fb64803 }
            // n = 7, score = 100
            //   8b8d50fcffff         | mov                 ecx, dword ptr [ebp - 0x3b0]
            //   8d148d34935500       | lea                 edx, [ecx*4 + 0x559334]
            //   899558fcffff         | mov                 dword ptr [ebp - 0x3a8], edx
            //   8d8d2cfeffff         | lea                 ecx, [ebp - 0x1d4]
            //   e8????????           |                     
            //   8b8558fcffff         | mov                 eax, dword ptr [ebp - 0x3a8]
            //   0fb64803             | movzx               ecx, byte ptr [eax + 3]

        $sequence_1 = { 46 4c 002c46 4c }
            // n = 4, score = 100
            //   46                   | inc                 esi
            //   4c                   | dec                 esp
            //   002c46               | add                 byte ptr [esi + eax*2], ch
            //   4c                   | dec                 esp

        $sequence_2 = { 83e23f 6bc230 8b0c8de0465600 8b540118 8955f4 837df4ff 7412 }
            // n = 7, score = 100
            //   83e23f               | and                 edx, 0x3f
            //   6bc230               | imul                eax, edx, 0x30
            //   8b0c8de0465600       | mov                 ecx, dword ptr [ecx*4 + 0x5646e0]
            //   8b540118             | mov                 edx, dword ptr [ecx + eax + 0x18]
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   837df4ff             | cmp                 dword ptr [ebp - 0xc], -1
            //   7412                 | je                  0x14

        $sequence_3 = { 8d8d74fcffff e8???????? eb1f 6a00 8d8560fcffff 50 8d8decfeffff }
            // n = 7, score = 100
            //   8d8d74fcffff         | lea                 ecx, [ebp - 0x38c]
            //   e8????????           |                     
            //   eb1f                 | jmp                 0x21
            //   6a00                 | push                0
            //   8d8560fcffff         | lea                 eax, [ebp - 0x3a0]
            //   50                   | push                eax
            //   8d8decfeffff         | lea                 ecx, [ebp - 0x114]

        $sequence_4 = { 8b4d08 51 8b4df8 e8???????? 8bf0 8b4df8 }
            // n = 6, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_5 = { 837d1800 740c c785d8deffffe8905400 eb0a c785d8deffff88905400 8b85a8deffff 50 }
            // n = 7, score = 100
            //   837d1800             | cmp                 dword ptr [ebp + 0x18], 0
            //   740c                 | je                  0xe
            //   c785d8deffffe8905400     | mov    dword ptr [ebp - 0x2128], 0x5490e8
            //   eb0a                 | jmp                 0xc
            //   c785d8deffff88905400     | mov    dword ptr [ebp - 0x2128], 0x549088
            //   8b85a8deffff         | mov                 eax, dword ptr [ebp - 0x2158]
            //   50                   | push                eax

        $sequence_6 = { f3ab 0fb64508 85c0 741b 837d0c00 7515 8b4514 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   0fb64508             | movzx               eax, byte ptr [ebp + 8]
            //   85c0                 | test                eax, eax
            //   741b                 | je                  0x1d
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7515                 | jne                 0x17
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

        $sequence_7 = { 8b00 50 8b4df8 e8???????? 8b08 51 8b4df8 }
            // n = 7, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_8 = { 85db 7552 68???????? 68???????? 56 6a41 68???????? }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   7552                 | jne                 0x54
            //   68????????           |                     
            //   68????????           |                     
            //   56                   | push                esi
            //   6a41                 | push                0x41
            //   68????????           |                     

        $sequence_9 = { 8b4508 8b0c853c255600 51 ff15???????? 8b5508 }
            // n = 5, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0c853c255600       | mov                 ecx, dword ptr [eax*4 + 0x56253c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 3031040
}