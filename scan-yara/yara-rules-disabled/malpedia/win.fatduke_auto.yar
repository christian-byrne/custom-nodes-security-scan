rule win_fatduke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.fatduke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fatduke"
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
        $sequence_0 = { 807b0d00 7552 ff7608 8bc8 e8???????? 8b36 8d7b10 }
            // n = 7, score = 200
            //   807b0d00             | cmp                 byte ptr [ebx + 0xd], 0
            //   7552                 | jne                 0x54
            //   ff7608               | push                dword ptr [esi + 8]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   8d7b10               | lea                 edi, [ebx + 0x10]

        $sequence_1 = { 8bcb 85f6 7455 83ee04 7211 8b01 3b02 }
            // n = 7, score = 200
            //   8bcb                 | mov                 ecx, ebx
            //   85f6                 | test                esi, esi
            //   7455                 | je                  0x57
            //   83ee04               | sub                 esi, 4
            //   7211                 | jb                  0x13
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   3b02                 | cmp                 eax, dword ptr [edx]

        $sequence_2 = { ff75f0 c746140f000000 c7461000000000 c60600 e8???????? 8b4b04 83c404 }
            // n = 7, score = 200
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c60600               | mov                 byte ptr [esi], 0
            //   e8????????           |                     
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   83c404               | add                 esp, 4

        $sequence_3 = { e8???????? c745c000000000 c745c400000000 c745c40f000000 c745c000000000 c645b000 3bc1 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c745c000000000       | mov                 dword ptr [ebp - 0x40], 0
            //   c745c400000000       | mov                 dword ptr [ebp - 0x3c], 0
            //   c745c40f000000       | mov                 dword ptr [ebp - 0x3c], 0xf
            //   c745c000000000       | mov                 dword ptr [ebp - 0x40], 0
            //   c645b000             | mov                 byte ptr [ebp - 0x50], 0
            //   3bc1                 | cmp                 eax, ecx

        $sequence_4 = { e8???????? 83c404 c745bc0f000000 c745b800000000 c645a800 c745fcffffffff 837dec10 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c745bc0f000000       | mov                 dword ptr [ebp - 0x44], 0xf
            //   c745b800000000       | mov                 dword ptr [ebp - 0x48], 0
            //   c645a800             | mov                 byte ptr [ebp - 0x58], 0
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   837dec10             | cmp                 dword ptr [ebp - 0x14], 0x10

        $sequence_5 = { c7864c01000000000000 c6863c01000000 c645fc0b 83be3801000010 720e ffb624010000 e8???????? }
            // n = 7, score = 200
            //   c7864c01000000000000     | mov    dword ptr [esi + 0x14c], 0
            //   c6863c01000000       | mov                 byte ptr [esi + 0x13c], 0
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   83be3801000010       | cmp                 dword ptr [esi + 0x138], 0x10
            //   720e                 | jb                  0x10
            //   ffb624010000         | push                dword ptr [esi + 0x124]
            //   e8????????           |                     

        $sequence_6 = { f7d3 23da 7419 2bf9 8bff 8a040f 8d4901 }
            // n = 7, score = 200
            //   f7d3                 | not                 ebx
            //   23da                 | and                 ebx, edx
            //   7419                 | je                  0x1b
            //   2bf9                 | sub                 edi, ecx
            //   8bff                 | mov                 edi, edi
            //   8a040f               | mov                 al, byte ptr [edi + ecx]
            //   8d4901               | lea                 ecx, [ecx + 1]

        $sequence_7 = { 83ec1c a1???????? 33c5 8945fc 8b4508 8b4910 8945e4 }
            // n = 7, score = 200
            //   83ec1c               | sub                 esp, 0x1c
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4910               | mov                 ecx, dword ptr [ecx + 0x10]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_8 = { 8d4e08 51 e8???????? c745fcffffffff 8bc6 8b4df4 64890d00000000 }
            // n = 7, score = 200
            //   8d4e08               | lea                 ecx, [esi + 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8bc6                 | mov                 eax, esi
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_9 = { ff75c0 e8???????? 83c404 c745d40f000000 8ac3 c745d000000000 c645c000 }
            // n = 7, score = 200
            //   ff75c0               | push                dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c745d40f000000       | mov                 dword ptr [ebp - 0x2c], 0xf
            //   8ac3                 | mov                 al, bl
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   c645c000             | mov                 byte ptr [ebp - 0x40], 0

    condition:
        7 of them and filesize < 9012224
}