rule win_starcruft_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.starcruft."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starcruft"
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
        $sequence_0 = { 83bd34fbffff00 7458 0fb64d34 85c9 7419 8b95b4fcffff 899558fbffff }
            // n = 7, score = 100
            //   83bd34fbffff00       | cmp                 dword ptr [ebp - 0x4cc], 0
            //   7458                 | je                  0x5a
            //   0fb64d34             | movzx               ecx, byte ptr [ebp + 0x34]
            //   85c9                 | test                ecx, ecx
            //   7419                 | je                  0x1b
            //   8b95b4fcffff         | mov                 edx, dword ptr [ebp - 0x34c]
            //   899558fbffff         | mov                 dword ptr [ebp - 0x4a8], edx

        $sequence_1 = { ebbd c7852cfeffff01000000 83bd2cfeffff00 7565 8b4508 898524feffff c78520feffff00000000 }
            // n = 7, score = 100
            //   ebbd                 | jmp                 0xffffffbf
            //   c7852cfeffff01000000     | mov    dword ptr [ebp - 0x1d4], 1
            //   83bd2cfeffff00       | cmp                 dword ptr [ebp - 0x1d4], 0
            //   7565                 | jne                 0x67
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   898524feffff         | mov                 dword ptr [ebp - 0x1dc], eax
            //   c78520feffff00000000     | mov    dword ptr [ebp - 0x1e0], 0

        $sequence_2 = { 884def 8b55f0 83c202 8955f0 8b45f0 8945f8 eb09 }
            // n = 7, score = 100
            //   884def               | mov                 byte ptr [ebp - 0x11], cl
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   83c202               | add                 edx, 2
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   eb09                 | jmp                 0xb

        $sequence_3 = { 8b55f8 8b85ccfeffff 8b0c90 0fb711 85d2 740b 8b45f8 }
            // n = 7, score = 100
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b85ccfeffff         | mov                 eax, dword ptr [ebp - 0x134]
            //   8b0c90               | mov                 ecx, dword ptr [eax + edx*4]
            //   0fb711               | movzx               edx, word ptr [ecx]
            //   85d2                 | test                edx, edx
            //   740b                 | je                  0xd
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_4 = { 55 8bec 81ec20010000 a1???????? 33c5 8945e4 8b4508 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec20010000         | sub                 esp, 0x120
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_5 = { c685cafcffff26 c685cbfcffffa1 c685ccfcffff8b c685cdfcffff52 c685cefcffff6c c685cffcffffba c685d0fcffffde }
            // n = 7, score = 100
            //   c685cafcffff26       | mov                 byte ptr [ebp - 0x336], 0x26
            //   c685cbfcffffa1       | mov                 byte ptr [ebp - 0x335], 0xa1
            //   c685ccfcffff8b       | mov                 byte ptr [ebp - 0x334], 0x8b
            //   c685cdfcffff52       | mov                 byte ptr [ebp - 0x333], 0x52
            //   c685cefcffff6c       | mov                 byte ptr [ebp - 0x332], 0x6c
            //   c685cffcffffba       | mov                 byte ptr [ebp - 0x331], 0xba
            //   c685d0fcffffde       | mov                 byte ptr [ebp - 0x330], 0xde

        $sequence_6 = { 8b4dd4 8908 8b5510 8b02 50 8d4dd8 51 }
            // n = 7, score = 100
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   50                   | push                eax
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   51                   | push                ecx

        $sequence_7 = { 8b4dcc 51 e8???????? 83c404 8945f0 8955f4 8b55d0 }
            // n = 7, score = 100
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]

        $sequence_8 = { e8???????? 83c404 33c0 e9???????? 8b45fc }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_9 = { e8???????? e8???????? c705????????04c02e00 c705????????08c02e00 c705????????0cc12e00 c705????????10c12e00 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   c705????????04c02e00     |     
            //   c705????????08c02e00     |     
            //   c705????????0cc12e00     |     
            //   c705????????10c12e00     |     

    condition:
        7 of them and filesize < 294912
}