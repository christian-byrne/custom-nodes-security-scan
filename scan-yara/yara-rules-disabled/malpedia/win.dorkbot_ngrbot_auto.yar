rule win_dorkbot_ngrbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dorkbot_ngrbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dorkbot_ngrbot"
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
        $sequence_0 = { 6a5c 56 e8???????? 8b5d0c 6a5c 53 8bf8 }
            // n = 7, score = 200
            //   6a5c                 | push                0x5c
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   6a5c                 | push                0x5c
            //   53                   | push                ebx
            //   8bf8                 | mov                 edi, eax

        $sequence_1 = { ffd6 33c0 a3???????? a3???????? a3???????? 8b45fc }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax
            //   a3????????           |                     
            //   a3????????           |                     
            //   a3????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_2 = { c1e704 8b8f84693a02 48 3bc8 0f8289000000 68???????? 8d45ec }
            // n = 7, score = 200
            //   c1e704               | shl                 edi, 4
            //   8b8f84693a02         | mov                 ecx, dword ptr [edi + 0x23a6984]
            //   48                   | dec                 eax
            //   3bc8                 | cmp                 ecx, eax
            //   0f8289000000         | jb                  0x8f
            //   68????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_3 = { 3bc6 751a 8b00 898120100000 8b0a 8bb920100000 56 }
            // n = 7, score = 200
            //   3bc6                 | cmp                 eax, esi
            //   751a                 | jne                 0x1c
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   898120100000         | mov                 dword ptr [ecx + 0x1020], eax
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   8bb920100000         | mov                 edi, dword ptr [ecx + 0x1020]
            //   56                   | push                esi

        $sequence_4 = { 8b4508 50 8d8da4fdffff 51 68???????? 8d958cf7ffff 6817060000 }
            // n = 7, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8d8da4fdffff         | lea                 ecx, [ebp - 0x25c]
            //   51                   | push                ecx
            //   68????????           |                     
            //   8d958cf7ffff         | lea                 edx, [ebp - 0x874]
            //   6817060000           | push                0x617

        $sequence_5 = { 8b15???????? 8b1d???????? 6a08 52 ffd3 6804010000 8906 }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   8b1d????????         |                     
            //   6a08                 | push                8
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   6804010000           | push                0x104
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_6 = { 0145fc ffd3 8bc8 b8d34d6210 f7e1 c1ea06 }
            // n = 6, score = 200
            //   0145fc               | add                 dword ptr [ebp - 4], eax
            //   ffd3                 | call                ebx
            //   8bc8                 | mov                 ecx, eax
            //   b8d34d6210           | mov                 eax, 0x10624dd3
            //   f7e1                 | mul                 ecx
            //   c1ea06               | shr                 edx, 6

        $sequence_7 = { 6689462d 83c007 66898638100000 5f 895628 c6462c03 b801000000 }
            // n = 7, score = 200
            //   6689462d             | mov                 word ptr [esi + 0x2d], ax
            //   83c007               | add                 eax, 7
            //   66898638100000       | mov                 word ptr [esi + 0x1038], ax
            //   5f                   | pop                 edi
            //   895628               | mov                 dword ptr [esi + 0x28], edx
            //   c6462c03             | mov                 byte ptr [esi + 0x2c], 3
            //   b801000000           | mov                 eax, 1

        $sequence_8 = { 53 8d55d4 52 ffd6 85c0 7fdb 5f }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   8d55d4               | lea                 edx, [ebp - 0x2c]
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7fdb                 | jg                  0xffffffdd
            //   5f                   | pop                 edi

        $sequence_9 = { 0fb6c9 6880000000 83c202 52 8b5508 f7d9 1bc9 }
            // n = 7, score = 200
            //   0fb6c9               | movzx               ecx, cl
            //   6880000000           | push                0x80
            //   83c202               | add                 edx, 2
            //   52                   | push                edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   f7d9                 | neg                 ecx
            //   1bc9                 | sbb                 ecx, ecx

    condition:
        7 of them and filesize < 638976
}