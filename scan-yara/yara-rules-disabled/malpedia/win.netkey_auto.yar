rule win_netkey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.netkey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netkey"
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
        $sequence_0 = { 83c40c 83c208 8bca 81e11f000080 7905 49 }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0xc
            //   83c208               | add                 edx, 8
            //   8bca                 | mov                 ecx, edx
            //   81e11f000080         | and                 ecx, 0x8000001f
            //   7905                 | jns                 7
            //   49                   | dec                 ecx

        $sequence_1 = { 83e03f c1ff06 6bd830 8b04bda8214400 f644032801 7444 837c0318ff }
            // n = 7, score = 200
            //   83e03f               | and                 eax, 0x3f
            //   c1ff06               | sar                 edi, 6
            //   6bd830               | imul                ebx, eax, 0x30
            //   8b04bda8214400       | mov                 eax, dword ptr [edi*4 + 0x4421a8]
            //   f644032801           | test                byte ptr [ebx + eax + 0x28], 1
            //   7444                 | je                  0x46
            //   837c0318ff           | cmp                 dword ptr [ebx + eax + 0x18], -1

        $sequence_2 = { 81ec98010000 a1???????? 33c4 89842494010000 b9???????? e8???????? 8d0424 }
            // n = 7, score = 200
            //   81ec98010000         | sub                 esp, 0x198
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842494010000       | mov                 dword ptr [esp + 0x194], eax
            //   b9????????           |                     
            //   e8????????           |                     
            //   8d0424               | lea                 eax, [esp]

        $sequence_3 = { 83c404 85ff 0f84c7000000 57 53 6a00 56 }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   85ff                 | test                edi, edi
            //   0f84c7000000         | je                  0xcd
            //   57                   | push                edi
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_4 = { 8bc2 8955fc 99 83e21f 8d0c02 c1f905 }
            // n = 6, score = 200
            //   8bc2                 | mov                 eax, edx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   99                   | cdq                 
            //   83e21f               | and                 edx, 0x1f
            //   8d0c02               | lea                 ecx, [edx + eax]
            //   c1f905               | sar                 ecx, 5

        $sequence_5 = { 6a01 8845e8 8d45e8 57 50 c745c801000000 e8???????? }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   8845e8               | mov                 byte ptr [ebp - 0x18], al
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   57                   | push                edi
            //   50                   | push                eax
            //   c745c801000000       | mov                 dword ptr [ebp - 0x38], 1
            //   e8????????           |                     

        $sequence_6 = { 42 668955ec e8???????? 99 be3b000000 f7fe }
            // n = 6, score = 200
            //   42                   | inc                 edx
            //   668955ec             | mov                 word ptr [ebp - 0x14], dx
            //   e8????????           |                     
            //   99                   | cdq                 
            //   be3b000000           | mov                 esi, 0x3b
            //   f7fe                 | idiv                esi

        $sequence_7 = { 780d b801000000 5f 5e 5b 59 }
            // n = 6, score = 200
            //   780d                 | js                  0xf
            //   b801000000           | mov                 eax, 1
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx

        $sequence_8 = { 83c8ff eb07 8b04cd8c6a4300 5f 5e 5b 8be5 }
            // n = 7, score = 200
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb07                 | jmp                 9
            //   8b04cd8c6a4300       | mov                 eax, dword ptr [ecx*8 + 0x436a8c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_9 = { 8d8fd8000000 e8???????? 0f1005???????? 8d95f0fbffff 8d4a01 0f1185f0fbffff }
            // n = 6, score = 200
            //   8d8fd8000000         | lea                 ecx, [edi + 0xd8]
            //   e8????????           |                     
            //   0f1005????????       |                     
            //   8d95f0fbffff         | lea                 edx, [ebp - 0x410]
            //   8d4a01               | lea                 ecx, [edx + 1]
            //   0f1185f0fbffff       | movups              xmmword ptr [ebp - 0x410], xmm0

    condition:
        7 of them and filesize < 606208
}