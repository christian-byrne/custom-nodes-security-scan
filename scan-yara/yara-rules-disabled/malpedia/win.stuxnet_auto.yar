rule win_stuxnet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.stuxnet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
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
        $sequence_0 = { e8???????? 8b5dec 8b45f0 895df4 8945f8 ff770c 8d75ec }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   8d75ec               | lea                 esi, [ebp - 0x14]

        $sequence_1 = { c20400 b8???????? e8???????? 51 6a08 e8???????? 59 }
            // n = 7, score = 200
            //   c20400               | ret                 4
            //   b8????????           |                     
            //   e8????????           |                     
            //   51                   | push                ecx
            //   6a08                 | push                8
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_2 = { e8???????? 33db 895dfc 53 8d45d8 50 6802000080 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   53                   | push                ebx
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   6802000080           | push                0x80000002

        $sequence_3 = { 6aff 68???????? 64a100000000 50 64892500000000 83ec64 8d442420 }
            // n = 7, score = 200
            //   6aff                 | push                -1
            //   68????????           |                     
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   83ec64               | sub                 esp, 0x64
            //   8d442420             | lea                 eax, [esp + 0x20]

        $sequence_4 = { eb02 33f6 c645fc00 8b4f1c 3bf1 740a 85c9 }
            // n = 7, score = 200
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8b4f1c               | mov                 ecx, dword ptr [edi + 0x1c]
            //   3bf1                 | cmp                 esi, ecx
            //   740a                 | je                  0xc
            //   85c9                 | test                ecx, ecx

        $sequence_5 = { 837df008 8b45dc 7303 8d45dc 50 8d431c e8???????? }
            // n = 7, score = 200
            //   837df008             | cmp                 dword ptr [ebp - 0x10], 8
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   7303                 | jae                 5
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   8d431c               | lea                 eax, [ebx + 0x1c]
            //   e8????????           |                     

        $sequence_6 = { c706???????? e8???????? c645fc01 c6462400 834dfcff 8b4df4 8bc6 }
            // n = 7, score = 200
            //   c706????????         |                     
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   c6462400             | mov                 byte ptr [esi + 0x24], 0
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { a5 50 a5 ff5130 85c0 7cb0 8b9b48080000 }
            // n = 7, score = 200
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   50                   | push                eax
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   85c0                 | test                eax, eax
            //   7cb0                 | jl                  0xffffffb2
            //   8b9b48080000         | mov                 ebx, dword ptr [ebx + 0x848]

        $sequence_8 = { ff750c ff7510 8d45e4 50 e8???????? c645fc01 8d4def }
            // n = 7, score = 200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8d4def               | lea                 ecx, [ebp - 0x11]

        $sequence_9 = { ff7508 8d4df4 e8???????? 837d14ff 7d04 33c0 eb12 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   e8????????           |                     
            //   837d14ff             | cmp                 dword ptr [ebp + 0x14], -1
            //   7d04                 | jge                 6
            //   33c0                 | xor                 eax, eax
            //   eb12                 | jmp                 0x14

    condition:
        7 of them and filesize < 2495488
}