rule win_xpan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xpan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpan"
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
        $sequence_0 = { 83c001 c7450cffffffff 894108 8b4108 3b410c 0f83cb050000 0fb600 }
            // n = 7, score = 400
            //   83c001               | add                 eax, 1
            //   c7450cffffffff       | mov                 dword ptr [ebp + 0xc], 0xffffffff
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   3b410c               | cmp                 eax, dword ptr [ecx + 0xc]
            //   0f83cb050000         | jae                 0x5d1
            //   0fb600               | movzx               eax, byte ptr [eax]

        $sequence_1 = { 8bb018010000 85f6 0f8557010000 8b01 89cd 83f84d 0f870d1d0000 }
            // n = 7, score = 400
            //   8bb018010000         | mov                 esi, dword ptr [eax + 0x118]
            //   85f6                 | test                esi, esi
            //   0f8557010000         | jne                 0x15d
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   89cd                 | mov                 ebp, ecx
            //   83f84d               | cmp                 eax, 0x4d
            //   0f870d1d0000         | ja                  0x1d13

        $sequence_2 = { 8b5d20 83e001 05ffffff7f 8903 8b451c c70004000000 807dbc00 }
            // n = 7, score = 400
            //   8b5d20               | mov                 ebx, dword ptr [ebp + 0x20]
            //   83e001               | and                 eax, 1
            //   05ffffff7f           | add                 eax, 0x7fffffff
            //   8903                 | mov                 dword ptr [ebx], eax
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   c70004000000         | mov                 dword ptr [eax], 4
            //   807dbc00             | cmp                 byte ptr [ebp - 0x44], 0

        $sequence_3 = { 8b442428 895c2404 89442408 ff15???????? 39c3 7247 }
            // n = 6, score = 400
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   ff15????????         |                     
            //   39c3                 | cmp                 ebx, eax
            //   7247                 | jb                  0x49

        $sequence_4 = { ffd5 83ec04 83fe05 75ea 8d7338 c7431cffffffff }
            // n = 6, score = 400
            //   ffd5                 | call                ebp
            //   83ec04               | sub                 esp, 4
            //   83fe05               | cmp                 esi, 5
            //   75ea                 | jne                 0xffffffec
            //   8d7338               | lea                 esi, [ebx + 0x38]
            //   c7431cffffffff       | mov                 dword ptr [ebx + 0x1c], 0xffffffff

        $sequence_5 = { 8b55d0 c645c201 0fbed8 0fb65210 e9???????? c645c100 c645c201 }
            // n = 7, score = 400
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   c645c201             | mov                 byte ptr [ebp - 0x3e], 1
            //   0fbed8               | movsx               ebx, al
            //   0fb65210             | movzx               edx, byte ptr [edx + 0x10]
            //   e9????????           |                     
            //   c645c100             | mov                 byte ptr [ebp - 0x3f], 0
            //   c645c201             | mov                 byte ptr [ebp - 0x3e], 1

        $sequence_6 = { 8b930c010000 88442418 be01000000 c683ff00000000 c7442404ff000000 891c24 89542408 }
            // n = 7, score = 400
            //   8b930c010000         | mov                 edx, dword ptr [ebx + 0x10c]
            //   88442418             | mov                 byte ptr [esp + 0x18], al
            //   be01000000           | mov                 esi, 1
            //   c683ff00000000       | mov                 byte ptr [ebx + 0xff], 0
            //   c7442404ff000000     | mov                 dword ptr [esp + 4], 0xff
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89542408             | mov                 dword ptr [esp + 8], edx

        $sequence_7 = { 0fb644242c 89442404 89f0 83c002 890424 e8???????? e9???????? }
            // n = 7, score = 400
            //   0fb644242c           | movzx               eax, byte ptr [esp + 0x2c]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   89f0                 | mov                 eax, esi
            //   83c002               | add                 eax, 2
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_8 = { e9???????? 8d489f 80f905 0f874b0e0000 83e857 e9???????? 8b931c010000 }
            // n = 7, score = 400
            //   e9????????           |                     
            //   8d489f               | lea                 ecx, [eax - 0x61]
            //   80f905               | cmp                 cl, 5
            //   0f874b0e0000         | ja                  0xe51
            //   83e857               | sub                 eax, 0x57
            //   e9????????           |                     
            //   8b931c010000         | mov                 edx, dword ptr [ebx + 0x11c]

        $sequence_9 = { 31c0 e9???????? 8b44241c 897c243c 89442438 8d442438 898310010000 }
            // n = 7, score = 400
            //   31c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   897c243c             | mov                 dword ptr [esp + 0x3c], edi
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   8d442438             | lea                 eax, [esp + 0x38]
            //   898310010000         | mov                 dword ptr [ebx + 0x110], eax

    condition:
        7 of them and filesize < 3235840
}