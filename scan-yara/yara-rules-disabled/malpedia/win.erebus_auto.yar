rule win_erebus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.erebus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erebus"
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
        $sequence_0 = { 8d4c243c 50 c744245000000000 e8???????? 8d742434 bb01000000 eb53 }
            // n = 7, score = 100
            //   8d4c243c             | lea                 ecx, [esp + 0x3c]
            //   50                   | push                eax
            //   c744245000000000     | mov                 dword ptr [esp + 0x50], 0
            //   e8????????           |                     
            //   8d742434             | lea                 esi, [esp + 0x34]
            //   bb01000000           | mov                 ebx, 1
            //   eb53                 | jmp                 0x55

        $sequence_1 = { ff15???????? 8b4514 8918 8bc7 5f 5b 8be5 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8918                 | mov                 dword ptr [eax], ebx
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_2 = { 8d45f0 50 8b8540ffffff 8d8d40ffffff 8b4004 03c8 e8???????? }
            // n = 7, score = 100
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8b8540ffffff         | mov                 eax, dword ptr [ebp - 0xc0]
            //   8d8d40ffffff         | lea                 ecx, [ebp - 0xc0]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   03c8                 | add                 ecx, eax
            //   e8????????           |                     

        $sequence_3 = { ff4718 40 ff7718 25ffff0000 50 68???????? 56 }
            // n = 7, score = 100
            //   ff4718               | inc                 dword ptr [edi + 0x18]
            //   40                   | inc                 eax
            //   ff7718               | push                dword ptr [edi + 0x18]
            //   25ffff0000           | and                 eax, 0xffff
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_4 = { 8d0c2a 894f18 740a 8b4704 034708 3bc8 7506 }
            // n = 7, score = 100
            //   8d0c2a               | lea                 ecx, [edx + ebp]
            //   894f18               | mov                 dword ptr [edi + 0x18], ecx
            //   740a                 | je                  0xc
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   034708               | add                 eax, dword ptr [edi + 8]
            //   3bc8                 | cmp                 ecx, eax
            //   7506                 | jne                 8

        $sequence_5 = { 8d4c2418 e8???????? 50 b9???????? c64424302e e8???????? c705????????24215000 }
            // n = 7, score = 100
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     
            //   50                   | push                eax
            //   b9????????           |                     
            //   c64424302e           | mov                 byte ptr [esp + 0x30], 0x2e
            //   e8????????           |                     
            //   c705????????24215000     |     

        $sequence_6 = { 50 57 53 e8???????? 83c418 8b8c2424020000 64890d00000000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8b8c2424020000       | mov                 ecx, dword ptr [esp + 0x224]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_7 = { c74704ffffffff c74710ffffffff c74714ffffffff 8b0f 8b4704 83f9ff 7504 }
            // n = 7, score = 100
            //   c74704ffffffff       | mov                 dword ptr [edi + 4], 0xffffffff
            //   c74710ffffffff       | mov                 dword ptr [edi + 0x10], 0xffffffff
            //   c74714ffffffff       | mov                 dword ptr [edi + 0x14], 0xffffffff
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   83f9ff               | cmp                 ecx, -1
            //   7504                 | jne                 6

        $sequence_8 = { 8bd0 c645fc1e 8d8d18ffffff e8???????? 8bf0 83c404 81fe???????? }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   c645fc1e             | mov                 byte ptr [ebp - 4], 0x1e
            //   8d8d18ffffff         | lea                 ecx, [ebp - 0xe8]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4
            //   81fe????????         |                     

        $sequence_9 = { 2b4718 034708 8b5710 0faf570c 3903 89442410 8d442414 }
            // n = 7, score = 100
            //   2b4718               | sub                 eax, dword ptr [edi + 0x18]
            //   034708               | add                 eax, dword ptr [edi + 8]
            //   8b5710               | mov                 edx, dword ptr [edi + 0x10]
            //   0faf570c             | imul                edx, dword ptr [edi + 0xc]
            //   3903                 | cmp                 dword ptr [ebx], eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8d442414             | lea                 eax, [esp + 0x14]

    condition:
        7 of them and filesize < 2564096
}