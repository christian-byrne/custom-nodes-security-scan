rule win_deltas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.deltas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltas"
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
        $sequence_0 = { 8d542434 898424d8000000 52 ffd6 898424d0000000 8d442458 50 }
            // n = 7, score = 200
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   898424d8000000       | mov                 dword ptr [esp + 0xd8], eax
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   898424d0000000       | mov                 dword ptr [esp + 0xd0], eax
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   50                   | push                eax

        $sequence_1 = { b22e b06c 51 c644240c77 c644240d73 c644240f5f c644241033 }
            // n = 7, score = 200
            //   b22e                 | mov                 dl, 0x2e
            //   b06c                 | mov                 al, 0x6c
            //   51                   | push                ecx
            //   c644240c77           | mov                 byte ptr [esp + 0xc], 0x77
            //   c644240d73           | mov                 byte ptr [esp + 0xd], 0x73
            //   c644240f5f           | mov                 byte ptr [esp + 0xf], 0x5f
            //   c644241033           | mov                 byte ptr [esp + 0x10], 0x33

        $sequence_2 = { c684241002000000 f3ab 66ab aa 8d442408 6804010000 50 }
            // n = 7, score = 200
            //   c684241002000000     | mov                 byte ptr [esp + 0x210], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d442408             | lea                 eax, [esp + 8]
            //   6804010000           | push                0x104
            //   50                   | push                eax

        $sequence_3 = { 8d742438 8dbc24f4000000 33c0 f3a5 b908000000 8d7c2418 }
            // n = 6, score = 200
            //   8d742438             | lea                 esi, [esp + 0x38]
            //   8dbc24f4000000       | lea                 edi, [esp + 0xf4]
            //   33c0                 | xor                 eax, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   b908000000           | mov                 ecx, 8
            //   8d7c2418             | lea                 edi, [esp + 0x18]

        $sequence_4 = { 68???????? 68???????? 50 ffd7 8d8c241c020000 6804010000 8d94241c010000 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8d8c241c020000       | lea                 ecx, [esp + 0x21c]
            //   6804010000           | push                0x104
            //   8d94241c010000       | lea                 edx, [esp + 0x11c]

        $sequence_5 = { 57 33f6 b922000000 33c0 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   b922000000           | mov                 ecx, 0x22
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 52 ffd6 898424e0000000 8d442440 50 ffd6 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   898424e0000000       | mov                 dword ptr [esp + 0xe0], eax
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_7 = { 894c242d 56 66894c2435 33f6 89442420 884c2437 57 }
            // n = 7, score = 200
            //   894c242d             | mov                 dword ptr [esp + 0x2d], ecx
            //   56                   | push                esi
            //   66894c2435           | mov                 word ptr [esp + 0x35], cx
            //   33f6                 | xor                 esi, esi
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   884c2437             | mov                 byte ptr [esp + 0x37], cl
            //   57                   | push                edi

        $sequence_8 = { 0bc1 33c7 0344242c 8d8410442229f4 8bd0 c1e006 c1ea1a }
            // n = 7, score = 200
            //   0bc1                 | or                  eax, ecx
            //   33c7                 | xor                 eax, edi
            //   0344242c             | add                 eax, dword ptr [esp + 0x2c]
            //   8d8410442229f4       | lea                 eax, [eax + edx - 0xbd6ddbc]
            //   8bd0                 | mov                 edx, eax
            //   c1e006               | shl                 eax, 6
            //   c1ea1a               | shr                 edx, 0x1a

        $sequence_9 = { c644245400 c684245801000000 f3ab 66ab }
            // n = 4, score = 200
            //   c644245400           | mov                 byte ptr [esp + 0x54], 0
            //   c684245801000000     | mov                 byte ptr [esp + 0x158], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax

    condition:
        7 of them and filesize < 90112
}