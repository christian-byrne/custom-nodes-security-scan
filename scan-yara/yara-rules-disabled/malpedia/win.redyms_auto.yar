rule win_redyms_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.redyms."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redyms"
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
        $sequence_0 = { 32d8 80f3fb 8819 40 41 6683f805 72ee }
            // n = 7, score = 100
            //   32d8                 | xor                 bl, al
            //   80f3fb               | xor                 bl, 0xfb
            //   8819                 | mov                 byte ptr [ecx], bl
            //   40                   | inc                 eax
            //   41                   | inc                 ecx
            //   6683f805             | cmp                 ax, 5
            //   72ee                 | jb                  0xfffffff0

        $sequence_1 = { 8b4604 50 6a00 ffd3 50 ffd7 56 }
            // n = 7, score = 100
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   56                   | push                esi

        $sequence_2 = { 33c5 8945fc 56 8b35???????? 8d4ddc 8bd1 }
            // n = 6, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   8bd1                 | mov                 edx, ecx

        $sequence_3 = { 85f6 0f84e4000000 8b3d???????? 8d4de8 8bd1 33c0 }
            // n = 6, score = 100
            //   85f6                 | test                esi, esi
            //   0f84e4000000         | je                  0xea
            //   8b3d????????         |                     
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   8bd1                 | mov                 edx, ecx
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { a1???????? 33c5 8945fc 56 c785ccfeffff04010000 7203 }
            // n = 6, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   c785ccfeffff04010000     | mov    dword ptr [ebp - 0x134], 0x104
            //   7203                 | jb                  5

        $sequence_5 = { c745d000000000 ff15???????? 5f 85c0 }
            // n = 4, score = 100
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   85c0                 | test                eax, eax

        $sequence_6 = { 7417 8b45f4 8b4df8 50 51 56 ff15???????? }
            // n = 7, score = 100
            //   7417                 | je                  0x19
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_7 = { 8b4608 8b4e04 50 6a00 e8???????? 83c408 }
            // n = 6, score = 100
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_8 = { 83c8ff 5b 8be5 5d c3 8bc6 5f }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi

        $sequence_9 = { 8d5828 53 8945fc ffd7 83caff 8bc6 f00fc110 }
            // n = 7, score = 100
            //   8d5828               | lea                 ebx, [eax + 0x28]
            //   53                   | push                ebx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ffd7                 | call                edi
            //   83caff               | or                  edx, 0xffffffff
            //   8bc6                 | mov                 eax, esi
            //   f00fc110             | lock xadd           dword ptr [eax], edx

    condition:
        7 of them and filesize < 98304
}