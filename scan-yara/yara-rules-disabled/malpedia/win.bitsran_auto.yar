rule win_bitsran_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bitsran."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bitsran"
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
        $sequence_0 = { 85c0 7433 56 57 8bbdf8bfffff c1ef02 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7433                 | je                  0x35
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bbdf8bfffff         | mov                 edi, dword ptr [ebp - 0x4008]
            //   c1ef02               | shr                 edi, 2

        $sequence_1 = { 8911 8b0d???????? 8b9d58fdffff eb5e 8b35???????? }
            // n = 5, score = 100
            //   8911                 | mov                 dword ptr [ecx], edx
            //   8b0d????????         |                     
            //   8b9d58fdffff         | mov                 ebx, dword ptr [ebp - 0x2a8]
            //   eb5e                 | jmp                 0x60
            //   8b35????????         |                     

        $sequence_2 = { 85f6 7417 8b4508 50 }
            // n = 4, score = 100
            //   85f6                 | test                esi, esi
            //   7417                 | je                  0x19
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax

        $sequence_3 = { 50 53 e8???????? 8b9d44fdffff 83ef04 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8b9d44fdffff         | mov                 ebx, dword ptr [ebp - 0x2bc]
            //   83ef04               | sub                 edi, 4

        $sequence_4 = { 83c408 85c0 7403 8975fc 8b03 8d55b8 52 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8d55b8               | lea                 edx, [ebp - 0x48]
            //   52                   | push                edx

        $sequence_5 = { 742b 8bc1 2bc1 c1f802 8d348500000000 }
            // n = 5, score = 100
            //   742b                 | je                  0x2d
            //   8bc1                 | mov                 eax, ecx
            //   2bc1                 | sub                 eax, ecx
            //   c1f802               | sar                 eax, 2
            //   8d348500000000       | lea                 esi, [eax*4]

        $sequence_6 = { 8b04c5046f4100 5d c3 8bff }
            // n = 4, score = 100
            //   8b04c5046f4100       | mov                 eax, dword ptr [eax*8 + 0x416f04]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_7 = { 8d95d4fbffff 52 53 ff15???????? 837d1401 7407 }
            // n = 6, score = 100
            //   8d95d4fbffff         | lea                 edx, [ebp - 0x42c]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   837d1401             | cmp                 dword ptr [ebp + 0x14], 1
            //   7407                 | je                  9

        $sequence_8 = { 2bc3 c1f802 3dfeffff3f 0f87d0010000 8bca 2bcb }
            // n = 6, score = 100
            //   2bc3                 | sub                 eax, ebx
            //   c1f802               | sar                 eax, 2
            //   3dfeffff3f           | cmp                 eax, 0x3ffffffe
            //   0f87d0010000         | ja                  0x1d6
            //   8bca                 | mov                 ecx, edx
            //   2bcb                 | sub                 ecx, ebx

        $sequence_9 = { 899d58fdffff 3bd9 0f83fe000000 3bd3 0f87f6000000 8b35???????? 2bda }
            // n = 7, score = 100
            //   899d58fdffff         | mov                 dword ptr [ebp - 0x2a8], ebx
            //   3bd9                 | cmp                 ebx, ecx
            //   0f83fe000000         | jae                 0x104
            //   3bd3                 | cmp                 edx, ebx
            //   0f87f6000000         | ja                  0xfc
            //   8b35????????         |                     
            //   2bda                 | sub                 ebx, edx

    condition:
        7 of them and filesize < 344064
}