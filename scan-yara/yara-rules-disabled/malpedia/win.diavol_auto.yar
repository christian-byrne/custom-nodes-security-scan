rule win_diavol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.diavol."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diavol"
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
        $sequence_0 = { ff15???????? 8bf0 83feff 0f8474010000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   0f8474010000         | je                  0x17a

        $sequence_1 = { 8d8df8fdffff 51 b9???????? e8???????? 83c404 84c0 }
            // n = 6, score = 100
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]
            //   51                   | push                ecx
            //   b9????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   84c0                 | test                al, al

        $sequence_2 = { 74cf 8bc7 ebce 66833800 7520 }
            // n = 5, score = 100
            //   74cf                 | je                  0xffffffd1
            //   8bc7                 | mov                 eax, edi
            //   ebce                 | jmp                 0xffffffd0
            //   66833800             | cmp                 word ptr [eax], 0
            //   7520                 | jne                 0x22

        $sequence_3 = { e8???????? 8b4df8 83c40c 5f 5e 33cd b001 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp
            //   b001                 | mov                 al, 1

        $sequence_4 = { 83fb01 7503 894df8 8b4d10 8bc3 }
            // n = 5, score = 100
            //   83fb01               | cmp                 ebx, 1
            //   7503                 | jne                 5
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8bc3                 | mov                 eax, ebx

        $sequence_5 = { 752c 6a02 53 ff15???????? }
            // n = 4, score = 100
            //   752c                 | jne                 0x2e
            //   6a02                 | push                2
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_6 = { e8???????? 83c40c 8b4dfc 5f 5e 33cd b001 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp
            //   b001                 | mov                 al, 1

        $sequence_7 = { 6a10 46 8d843594f7ffff 68???????? 50 e8???????? }
            // n = 6, score = 100
            //   6a10                 | push                0x10
            //   46                   | inc                 esi
            //   8d843594f7ffff       | lea                 eax, [ebp + esi - 0x86c]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 8d45e4 50 8bc8 51 57 8bd0 }
            // n = 6, score = 100
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   8bc8                 | mov                 ecx, eax
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8bd0                 | mov                 edx, eax

        $sequence_9 = { 0f84ee000000 53 57 33db 8d9b00000000 }
            // n = 5, score = 100
            //   0f84ee000000         | je                  0xf4
            //   53                   | push                ebx
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   8d9b00000000         | lea                 ebx, [ebx]

    condition:
        7 of them and filesize < 191488
}