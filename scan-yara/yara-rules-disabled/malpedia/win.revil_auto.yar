rule win_revil_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.revil."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
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
        $sequence_0 = { 334f1c 83c720 d1f8 83e801 89450c e9???????? 8b7510 }
            // n = 7, score = 4600
            //   334f1c               | xor                 ecx, dword ptr [edi + 0x1c]
            //   83c720               | add                 edi, 0x20
            //   d1f8                 | sar                 eax, 1
            //   83e801               | sub                 eax, 1
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   e9????????           |                     
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]

        $sequence_1 = { 50 e8???????? 8b7d08 8db568ffffff 83c414 }
            // n = 5, score = 4600
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8db568ffffff         | lea                 esi, [ebp - 0x98]
            //   83c414               | add                 esp, 0x14

        $sequence_2 = { 83e801 eb07 b00a 5d c3 83e862 7428 }
            // n = 7, score = 4600
            //   83e801               | sub                 eax, 1
            //   eb07                 | jmp                 9
            //   b00a                 | mov                 al, 0xa
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   83e862               | sub                 eax, 0x62
            //   7428                 | je                  0x2a

        $sequence_3 = { 8d8510ffffff 50 8d8560ffffff 50 8d45b0 50 e8???????? }
            // n = 7, score = 4600
            //   8d8510ffffff         | lea                 eax, [ebp - 0xf0]
            //   50                   | push                eax
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   50                   | push                eax
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { ff750c 8d45b0 50 8d85c0feffff 50 }
            // n = 5, score = 4600
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   50                   | push                eax

        $sequence_5 = { 8b4508 8b404c 8945f0 8b45e8 894b28 f7d0 23c2 }
            // n = 7, score = 4600
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b404c               | mov                 eax, dword ptr [eax + 0x4c]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   894b28               | mov                 dword ptr [ebx + 0x28], ecx
            //   f7d0                 | not                 eax
            //   23c2                 | and                 eax, edx

        $sequence_6 = { 334de0 8b4048 8b5d08 8945ec 8b4508 }
            // n = 5, score = 4600
            //   334de0               | xor                 ecx, dword ptr [ebp - 0x20]
            //   8b4048               | mov                 eax, dword ptr [eax + 0x48]
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_7 = { ff7520 e8???????? 8d8580feffff 50 ff7524 }
            // n = 5, score = 4600
            //   ff7520               | push                dword ptr [ebp + 0x20]
            //   e8????????           |                     
            //   8d8580feffff         | lea                 eax, [ebp - 0x180]
            //   50                   | push                eax
            //   ff7524               | push                dword ptr [ebp + 0x24]

        $sequence_8 = { 8975d8 0fb645ff 0bc8 8bc1 894dd8 }
            // n = 5, score = 4600
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   0bc8                 | or                  ecx, eax
            //   8bc1                 | mov                 eax, ecx
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx

        $sequence_9 = { 83e813 0f8461060000 83e83d 0f84fa020000 f6c204 7411 80f92c }
            // n = 7, score = 4600
            //   83e813               | sub                 eax, 0x13
            //   0f8461060000         | je                  0x667
            //   83e83d               | sub                 eax, 0x3d
            //   0f84fa020000         | je                  0x300
            //   f6c204               | test                dl, 4
            //   7411                 | je                  0x13
            //   80f92c               | cmp                 cl, 0x2c

    condition:
        7 of them and filesize < 155794432
}