rule win_diceloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.diceloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diceloader"
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
        $sequence_0 = { 7419 e8???????? 8bf0 83f8fe 0f840a010000 83f8ff }
            // n = 6, score = 100
            //   7419                 | lea                 edx, [0x117]
            //   e8????????           |                     
            //   8bf0                 | dec                 eax
            //   83f8fe               | arpl                word ptr [edi + 8], bp
            //   0f840a010000         | mov                 edx, 8
            //   83f8ff               | mov                 dword ptr [ebp + 0x5f8], ecx

        $sequence_1 = { 75cf 488325????????00 488d0d3a220000 448905???????? c705????????01000000 ff15???????? 488325????????00 }
            // n = 7, score = 100
            //   75cf                 | imul                eax, ecx, 7
            //   488325????????00     |                     
            //   488d0d3a220000       | dec                 eax
            //   448905????????       |                     
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   488325????????00     |                     

        $sequence_2 = { 75e5 448d4301 41b9983a0000 488d1daa2a0000 8bcf 488bd3 ff15???????? }
            // n = 7, score = 100
            //   75e5                 | inc                 ebp
            //   448d4301             | lea                 ebp, [esi + 4]
            //   41b9983a0000         | add                 al, bl
            //   488d1daa2a0000       | mov                 byte ptr [ebp + 0x61], al
            //   8bcf                 | inc                 ebp
            //   488bd3               | xor                 esp, esp
            //   ff15????????         |                     

        $sequence_3 = { 8b0491 4903c5 498907 33c9 eb2a }
            // n = 5, score = 100
            //   8b0491               | inc                 ebp
            //   4903c5               | xor                 eax, eax
            //   498907               | lea                 ecx, [edx + 6]
            //   33c9                 | call                eax
            //   eb2a                 | and                 dword ptr [ebx + 8], 0

        $sequence_4 = { 498b7318 498be3 5f c3 4053 4883ec20 33db }
            // n = 7, score = 100
            //   498b7318             | dec                 esp
            //   498be3               | mov                 esp, esi
            //   5f                   | inc                 esp
            //   c3                   | lea                 ecx, [ecx + 0x40]
            //   4053                 | dec                 ecx
            //   4883ec20             | cmovne              eax, esp
            //   33db                 | dec                 esp

        $sequence_5 = { 7453 33d2 458d460e 488d4c2420 e8???????? 0fb7ce }
            // n = 6, score = 100
            //   7453                 | je                  0xc59
            //   33d2                 | shr                 eax, 2
            //   458d460e             | imul                eax, eax, 7
            //   488d4c2420           | sub                 ebx, eax
            //   e8????????           |                     
            //   0fb7ce               | jne                 0xc7d

        $sequence_6 = { 8bf0 83f8fe 0f840a010000 83f8ff 0f8406010000 4533ff 3bf3 }
            // n = 7, score = 100
            //   8bf0                 | dec                 esp
            //   83f8fe               | sub                 ecx, dword ptr [ebp + 0x30]
            //   0f840a010000         | test                eax, eax
            //   83f8ff               | jne                 0x18e1
            //   0f8406010000         | dec                 esp
            //   4533ff               | mov                 edi, dword ptr [esp + 0x98]
            //   3bf3                 | inc                 esp

        $sequence_7 = { 4c8d4820 ba05000000 44894024 448bc1 c740e808000000 8d4afe e8???????? }
            // n = 7, score = 100
            //   4c8d4820             | xor                 edx, edx
            //   ba05000000           | dec                 esp
            //   44894024             | arpl                bx, ax
            //   448bc1               | dec                 eax
            //   c740e808000000       | lea                 ecx, [edi + 0x13]
            //   8d4afe               | dec                 eax
            //   e8????????           |                     

        $sequence_8 = { e8???????? 498bd5 488d0dea1f0000 e8???????? }
            // n = 4, score = 100
            //   e8????????           |                     
            //   498bd5               | mov                 edi, dword ptr [esp + 0x98]
            //   488d0dea1f0000       | dec                 ecx
            //   e8????????           |                     

        $sequence_9 = { 8d4860 e8???????? 488bcd 488bf8 895808 }
            // n = 5, score = 100
            //   8d4860               | test                eax, eax
            //   e8????????           |                     
            //   488bcd               | jne                 0x22c
            //   488bf8               | dec                 esp
            //   895808               | mov                 edi, dword ptr [esp + 0x98]

    condition:
        7 of them and filesize < 41984
}