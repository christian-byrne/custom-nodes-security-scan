rule win_wannahusky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.wannahusky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wannahusky"
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
        $sequence_0 = { eb0c 3d00010000 19c9 f7d1 83e108 d3e8 0fbe80e0184100 }
            // n = 7, score = 100
            //   eb0c                 | jmp                 0xe
            //   3d00010000           | cmp                 eax, 0x100
            //   19c9                 | sbb                 ecx, ecx
            //   f7d1                 | not                 ecx
            //   83e108               | and                 ecx, 8
            //   d3e8                 | shr                 eax, cl
            //   0fbe80e0184100       | movsx               eax, byte ptr [eax + 0x4118e0]

        $sequence_1 = { c7442404ffffffff c7042400000000 e8???????? 89d9 }
            // n = 4, score = 100
            //   c7442404ffffffff     | mov                 dword ptr [esp + 4], 0xffffffff
            //   c7042400000000       | mov                 dword ptr [esp], 0
            //   e8????????           |                     
            //   89d9                 | mov                 ecx, ebx

        $sequence_2 = { 8b08 e8???????? 84c0 7449 c78554fbffff00000000 a1???????? }
            // n = 6, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7449                 | je                  0x4b
            //   c78554fbffff00000000     | mov    dword ptr [ebp - 0x4ac], 0
            //   a1????????           |                     

        $sequence_3 = { 7405 8b08 83c11a e8???????? ba???????? e8???????? }
            // n = 6, score = 100
            //   7405                 | je                  7
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83c11a               | add                 ecx, 0x1a
            //   e8????????           |                     
            //   ba????????           |                     
            //   e8????????           |                     

        $sequence_4 = { e9???????? 8b4dc0 394dbc 7212 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   394dbc               | cmp                 dword ptr [ebp - 0x44], ecx
            //   7212                 | jb                  0x14

        $sequence_5 = { 66c705????????1101 c605????????01 c705????????2c000000 c705????????80ba4100 c705????????0c1e4100 }
            // n = 5, score = 100
            //   66c705????????1101     |     
            //   c605????????01       |                     
            //   c705????????2c000000     |     
            //   c705????????80ba4100     |     
            //   c705????????0c1e4100     |     

        $sequence_6 = { 8d57ff 89542404 e8???????? 8b45bc 8b4db8 }
            // n = 5, score = 100
            //   8d57ff               | lea                 edx, [edi - 1]
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   e8????????           |                     
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]

        $sequence_7 = { 89c1 58 5b 5d e9???????? 55 }
            // n = 6, score = 100
            //   89c1                 | mov                 ecx, eax
            //   58                   | pop                 eax
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_8 = { c705????????78b54100 c705????????00000000 c705????????04000000 c705????????04000000 }
            // n = 4, score = 100
            //   c705????????78b54100     |     
            //   c705????????00000000     |     
            //   c705????????04000000     |     
            //   c705????????04000000     |     

        $sequence_9 = { c705????????14000000 c705????????00484200 c705????????b41d4100 c705????????30b54100 c705????????00000000 c705????????04000000 }
            // n = 6, score = 100
            //   c705????????14000000     |     
            //   c705????????00484200     |     
            //   c705????????b41d4100     |     
            //   c705????????30b54100     |     
            //   c705????????00000000     |     
            //   c705????????04000000     |     

    condition:
        7 of them and filesize < 862208
}