rule win_sidetwist_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sidetwist."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidetwist"
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
        $sequence_0 = { c644244600 4839d0 0f833a020000 488b4c2450 837c2458ff 0f94c0 4885c9 }
            // n = 7, score = 100
            //   c644244600           | dec                 eax
            //   4839d0               | lea                 edx, [0xfff84f96]
            //   0f833a020000         | push                ebx
            //   488b4c2450           | dec                 eax
            //   837c2458ff           | sub                 esp, 0x58
            //   0f94c0               | dec                 eax
            //   4885c9               | mov                 esi, ecx

        $sequence_1 = { e8???????? 807e2000 48898424b0000000 7412 488d8c24b0000000 ba20000000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   807e2000             | jb                  0xfb
            //   48898424b0000000     | nop                 word ptr cs:[eax + eax]
            //   7412                 | dec                 eax
            //   488d8c24b0000000     | mov                 eax, dword ptr [edi]
            //   ba20000000           | dec                 eax
            //   e8????????           |                     

        $sequence_2 = { 4488742457 0fb6442457 4c8db42494000000 4c8d4c2460 4889fa 4c89742440 488d8c2480000000 }
            // n = 7, score = 100
            //   4488742457           | dec                 eax
            //   0fb6442457           | mov                 ecx, dword ptr [edi + esi*8 - 8]
            //   4c8db42494000000     | test                eax, eax
            //   4c8d4c2460           | jne                 0x788
            //   4889fa               | nop                 dword ptr [eax]
            //   4c89742440           | dec                 eax
            //   488d8c2480000000     | test                esi, esi

        $sequence_3 = { 89c8 884520 807d2040 7612 807d205a 770c 0fb64520 }
            // n = 7, score = 100
            //   89c8                 | dec                 eax
            //   884520               | add                 esp, 0x28
            //   807d2040             | dec                 ecx
            //   7612                 | mov                 ecx, edx
            //   807d205a             | dec                 ebp
            //   770c                 | cmova               eax, ecx
            //   0fb64520             | dec                 ecx

        $sequence_4 = { 896e18 4809c3 4889f8 488917 48895f08 4883c458 5b }
            // n = 7, score = 100
            //   896e18               | lea                 ecx, [esp + 0x50]
            //   4809c3               | dec                 eax
            //   4889f8               | mov                 dword ptr [esp + 0x30], ecx
            //   488917               | dec                 eax
            //   48895f08             | mov                 ecx, dword ptr [esp + 0xd8]
            //   4883c458             | dec                 esp
            //   5b                   | mov                 dword ptr [esp + 0x60], edx

        $sequence_5 = { bfffffffff 41bfffffffff e9???????? c644246c00 8844246e e9???????? 488b03 }
            // n = 7, score = 100
            //   bfffffffff           | dec                 eax
            //   41bfffffffff         | mov                 eax, dword ptr [ecx]
            //   e9????????           |                     
            //   c644246c00           | dec                 eax
            //   8844246e             | mov                 ebx, ecx
            //   e9????????           |                     
            //   488b03               | dec                 eax

        $sequence_6 = { 4c29cb 4c39c3 490f47d8 4885db 7411 480310 4883fb01 }
            // n = 7, score = 100
            //   4c29cb               | dec                 eax
            //   4c39c3               | mov                 eax, dword ptr [eax + 8]
            //   490f47d8             | dec                 eax
            //   4885db               | cmp                 eax, edx
            //   7411                 | jne                 0x30f
            //   480310               | mov                 ecx, dword ptr [esi]
            //   4883fb01             | dec                 eax

        $sequence_7 = { 7218 4c8b05???????? 458b08 4585c9 755e 448b41f8 4585c0 }
            // n = 7, score = 100
            //   7218                 | mov                 dword ptr [esi + 0x58], 0
            //   4c8b05????????       |                     
            //   458b08               | dec                 eax
            //   4585c9               | mov                 dword ptr [esi + 0x5c], 0
            //   755e                 | mov                 byte ptr [esi + 0x6f], 0
            //   448b41f8             | dec                 eax
            //   4585c0               | mov                 ecx, dword ptr [ebp + 0xd0]

        $sequence_8 = { 89c7 440fb603 29df c1e702 4885c0 b800000000 0f44f8 }
            // n = 7, score = 100
            //   89c7                 | dec                 eax
            //   440fb603             | mov                 dword ptr [ebx + 0x10], edi
            //   29df                 | dec                 esp
            //   c1e702               | lea                 ecx, [esp + 0x80]
            //   4885c0               | dec                 eax
            //   b800000000           | mov                 dword ptr [esp + 0x48], eax
            //   0f44f8               | dec                 eax

        $sequence_9 = { 6690 4885d2 7521 448b1e 4585db 0f8524020000 8b05???????? }
            // n = 7, score = 100
            //   6690                 | call                dword ptr [eax + 0x48]
            //   4885d2               | mov                 ebx, eax
            //   7521                 | cmp                 eax, -1
            //   448b1e               | dec                 eax
            //   4585db               | mov                 dword ptr [ebp - 0x18], 0
            //   0f8524020000         | dec                 eax
            //   8b05????????         |                     

    condition:
        7 of them and filesize < 2002944
}