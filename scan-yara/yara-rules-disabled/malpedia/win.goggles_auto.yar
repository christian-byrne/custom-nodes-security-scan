rule win_goggles_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.goggles."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goggles"
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
        $sequence_0 = { c1fa02 83e23f 8a8a10400010 880c33 }
            // n = 4, score = 100
            //   c1fa02               | sar                 edx, 2
            //   83e23f               | and                 edx, 0x3f
            //   8a8a10400010         | mov                 cl, byte ptr [edx + 0x10004010]
            //   880c33               | mov                 byte ptr [ebx + esi], cl

        $sequence_1 = { 51 e8???????? 8b1d???????? b941000000 33c0 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b1d????????         |                     
            //   b941000000           | mov                 ecx, 0x41
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 8d54247c 51 52 8d842488010000 68???????? 50 }
            // n = 6, score = 100
            //   8d54247c             | lea                 edx, [esp + 0x7c]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d842488010000       | lea                 eax, [esp + 0x188]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 6a01 51 ff15???????? 8b742430 8b542431 }
            // n = 5, score = 100
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b742430             | mov                 esi, dword ptr [esp + 0x30]
            //   8b542431             | mov                 edx, dword ptr [esp + 0x31]

        $sequence_4 = { 53 ff15???????? 83c414 33c0 85ed }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   33c0                 | xor                 eax, eax
            //   85ed                 | test                ebp, ebp

        $sequence_5 = { 51 ff15???????? 83c9ff bf???????? 33c0 83c414 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   bf????????           |                     
            //   33c0                 | xor                 eax, eax
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { c744241002000000 8d8c2480020000 51 ff15???????? 8b442410 5f 5e }
            // n = 7, score = 100
            //   c744241002000000     | mov                 dword ptr [esp + 0x10], 2
            //   8d8c2480020000       | lea                 ecx, [esp + 0x280]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { ffd5 8bf0 8bc7 99 f77c242c 81ee???????? 0fbe8288410010 }
            // n = 7, score = 100
            //   ffd5                 | call                ebp
            //   8bf0                 | mov                 esi, eax
            //   8bc7                 | mov                 eax, edi
            //   99                   | cdq                 
            //   f77c242c             | idiv                dword ptr [esp + 0x2c]
            //   81ee????????         |                     
            //   0fbe8288410010       | movsx               eax, byte ptr [edx + 0x10004188]

        $sequence_8 = { 2bd6 56 57 03ea ffd3 57 }
            // n = 6, score = 100
            //   2bd6                 | sub                 edx, esi
            //   56                   | push                esi
            //   57                   | push                edi
            //   03ea                 | add                 ebp, edx
            //   ffd3                 | call                ebx
            //   57                   | push                edi

        $sequence_9 = { a0???????? 55 57 88442410 }
            // n = 4, score = 100
            //   a0????????           |                     
            //   55                   | push                ebp
            //   57                   | push                edi
            //   88442410             | mov                 byte ptr [esp + 0x10], al

    condition:
        7 of them and filesize < 57344
}