rule win_arkei_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.arkei_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arkei_stealer"
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
        $sequence_0 = { 8d55c4 52 6a18 50 ff15???????? 85c0 }
            // n = 6, score = 400
            //   8d55c4               | lea                 edx, [ebp - 0x3c]
            //   52                   | push                edx
            //   6a18                 | push                0x18
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_1 = { 8be5 5d c3 50 8b45e8 }
            // n = 5, score = 400
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   50                   | push                eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_2 = { 894614 897e24 ff15???????? 8bd8 3bdf 0f84e3feffff }
            // n = 6, score = 400
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   897e24               | mov                 dword ptr [esi + 0x24], edi
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   3bdf                 | cmp                 ebx, edi
            //   0f84e3feffff         | je                  0xfffffee9

        $sequence_3 = { 8bf0 ffd3 8bd8 53 56 }
            // n = 5, score = 400
            //   8bf0                 | mov                 esi, eax
            //   ffd3                 | call                ebx
            //   8bd8                 | mov                 ebx, eax
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_4 = { 56 53 52 57 50 51 ff15???????? }
            // n = 7, score = 400
            //   56                   | push                esi
            //   53                   | push                ebx
            //   52                   | push                edx
            //   57                   | push                edi
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_5 = { 8b00 50 ff15???????? 83f8ff 740b a810 7507 }
            // n = 7, score = 400
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   740b                 | je                  0xd
            //   a810                 | test                al, 0x10
            //   7507                 | jne                 9

        $sequence_6 = { 85c0 0f8458feffff 8b4e20 6a00 8d45e4 50 8d148d28000000 }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   0f8458feffff         | je                  0xfffffe5e
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   6a00                 | push                0
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   8d148d28000000       | lea                 edx, [ecx*4 + 0x28]

        $sequence_7 = { 8bf0 c70628000000 8b4dc8 894e04 8b55cc 895608 668b45d4 }
            // n = 7, score = 400
            //   8bf0                 | mov                 esi, eax
            //   c70628000000         | mov                 dword ptr [esi], 0x28
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   894e04               | mov                 dword ptr [esi + 4], ecx
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   895608               | mov                 dword ptr [esi + 8], edx
            //   668b45d4             | mov                 ax, word ptr [ebp - 0x2c]

        $sequence_8 = { 8b7614 6a00 8d45e4 50 56 }
            // n = 5, score = 400
            //   8b7614               | mov                 esi, dword ptr [esi + 0x14]
            //   6a00                 | push                0
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_9 = { 56 894590 ff15???????? 8bf8 897d94 83ffff }
            // n = 6, score = 400
            //   56                   | push                esi
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   897d94               | mov                 dword ptr [ebp - 0x6c], edi
            //   83ffff               | cmp                 edi, -1

    condition:
        7 of them and filesize < 1744896
}