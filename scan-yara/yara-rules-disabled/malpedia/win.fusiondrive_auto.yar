rule win_fusiondrive_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.fusiondrive."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fusiondrive"
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
        $sequence_0 = { 48898620020000 0fb7c0 66f3ab 488d3d501c0100 482bfe 8a041f }
            // n = 6, score = 100
            //   48898620020000       | mov                 dword ptr [esp + 0x60], 0x6e72656b
            //   0fb7c0               | mov                 dword ptr [esp + 0x64], 0x32336c65
            //   66f3ab               | mov                 dword ptr [esp + 0x68], 0x6c6c642e
            //   488d3d501c0100       | mov                 byte ptr [esp + 0x6c], 0
            //   482bfe               | dec                 eax
            //   8a041f               | lea                 ecx, [esp + 0x60]

        $sequence_1 = { 0f846f010000 660f6f05???????? f30f7f442470 66c745806557 c6458200 488d542470 488bc8 }
            // n = 7, score = 100
            //   0f846f010000         | inc                 ecx
            //   660f6f05????????     |                     
            //   f30f7f442470         | mov                 eax, edx
            //   66c745806557         | dec                 ebx
            //   c6458200             | xchg                dword ptr [esi + edi*8 + 0x1df00], edi
            //   488d542470           | xor                 eax, eax
            //   488bc8               | dec                 eax

        $sequence_2 = { 7735 488bd1 4983ff08 7203 }
            // n = 4, score = 100
            //   7735                 | mov                 eax, 0x7c
            //   488bd1               | sub                 al, cl
            //   4983ff08             | inc                 ecx
            //   7203                 | dec                 eax

        $sequence_3 = { 4c8d4c2440 4983fd08 4d0f43cf 488d7c2420 4983fc08 490f43fa 4c8b5c2450 }
            // n = 7, score = 100
            //   4c8d4c2440           | dec                 eax
            //   4983fd08             | lea                 edx, [0xb776]
            //   4d0f43cf             | test                eax, eax
            //   488d7c2420           | je                  0xbde
            //   4983fc08             | inc                 ebp
            //   490f43fa             | xor                 eax, eax
            //   4c8b5c2450           | inc                 ebp

        $sequence_4 = { 4863c9 4c8d0514070100 488bc1 83e13f 48c1f806 488d14c9 498b04c0 }
            // n = 7, score = 100
            //   4863c9               | lea                 ebx, [0x128e3]
            //   4c8d0514070100       | dec                 eax
            //   488bc1               | mov                 ecx, dword ptr [ebx]
            //   83e13f               | dec                 eax
            //   48c1f806             | test                ecx, ecx
            //   488d14c9             | je                  0xb79
            //   498b04c0             | test                bl, bl

        $sequence_5 = { 0fb60a 83e10f 4c8d05f899ffff 4a0fbe8401a8150100 }
            // n = 4, score = 100
            //   0fb60a               | shr                 dword ptr [esp + 0x80], 3
            //   83e10f               | inc                 ecx
            //   4c8d05f899ffff       | mov                 eax, edi
            //   4a0fbe8401a8150100     | sub    eax, ebx

        $sequence_6 = { 488b542450 488bc8 488902 488b5310 ff15???????? 33c0 }
            // n = 6, score = 100
            //   488b542450           | lea                 ecx, [0x16e2b]
            //   488bc8               | dec                 eax
            //   488902               | mov                 dword ptr [eax], ecx
            //   488b5310             | dec                 eax
            //   ff15????????         |                     
            //   33c0                 | lea                 ecx, [0x16e81]

        $sequence_7 = { ff15???????? 8d0c4501000000 4103cf 458d7c2402 418bd7 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8d0c4501000000       | sub                 ax, cx
            //   4103cf               | inc                 ecx
            //   458d7c2402           | xor                 word ptr [edx], ax
            //   418bd7               | dec                 eax

        $sequence_8 = { ff15???????? 3db7000000 0f8432060000 33ff 8bcf }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   3db7000000           | sub                 ax, cx
            //   0f8432060000         | inc                 ecx
            //   33ff                 | xor                 word ptr [edx], ax
            //   8bcf                 | dec                 eax

        $sequence_9 = { 7528 48897df7 48c745ff07000000 66897de7 }
            // n = 4, score = 100
            //   7528                 | dec                 eax
            //   48897df7             | lea                 edx, [0x1b96e]
            //   48c745ff07000000     | mov                 eax, 0x11
            //   66897de7             | sub                 ax, cx

    condition:
        7 of them and filesize < 290816
}