rule win_sendsafe_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sendsafe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sendsafe"
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
        $sequence_0 = { ff36 f30f6f442438 8d442428 50 660fefc8 50 8b4608 }
            // n = 7, score = 200
            //   ff36                 | push                dword ptr [esi]
            //   f30f6f442438         | movdqu              xmm0, xmmword ptr [esp + 0x38]
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   660fefc8             | pxor                xmm1, xmm0
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]

        $sequence_1 = { f20f5e15???????? f20f59ca f20f58c1 f20f2cc8 894dd4 8b550c 83ba381c000000 }
            // n = 7, score = 200
            //   f20f5e15????????     |                     
            //   f20f59ca             | mulsd               xmm1, xmm2
            //   f20f58c1             | addsd               xmm0, xmm1
            //   f20f2cc8             | cvttsd2si           ecx, xmm0
            //   894dd4               | mov                 dword ptr [ebp - 0x2c], ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   83ba381c000000       | cmp                 dword ptr [edx + 0x1c38], 0

        $sequence_2 = { e8???????? 8b8510feffff e9???????? 6800010000 8b9588feffff 52 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b8510feffff         | mov                 eax, dword ptr [ebp - 0x1f0]
            //   e9????????           |                     
            //   6800010000           | push                0x100
            //   8b9588feffff         | mov                 edx, dword ptr [ebp - 0x178]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_3 = { c1e000 8b4dfc 0fbe1401 85d2 7409 8b45f8 83c001 }
            // n = 7, score = 200
            //   c1e000               | shl                 eax, 0
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   0fbe1401             | movsx               edx, byte ptr [ecx + eax]
            //   85d2                 | test                edx, edx
            //   7409                 | je                  0xb
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c001               | add                 eax, 1

        $sequence_4 = { e8???????? 83c40c 8983b0010000 85c0 750a 6815060000 e9???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8983b0010000         | mov                 dword ptr [ebx + 0x1b0], eax
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   6815060000           | push                0x615
            //   e9????????           |                     

        $sequence_5 = { e8???????? 83c414 85c0 0f84e1010000 ff7518 8d4704 57 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   0f84e1010000         | je                  0x1e7
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   8d4704               | lea                 eax, [edi + 4]
            //   57                   | push                edi

        $sequence_6 = { eb07 c745fc00000000 8b5508 8b4204 3b45fc 7404 33c0 }
            // n = 7, score = 200
            //   eb07                 | jmp                 9
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   3b45fc               | cmp                 eax, dword ptr [ebp - 4]
            //   7404                 | je                  6
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 8b783c 037904 8b8610010000 8bef c1f808 896c2414 8807 }
            // n = 7, score = 200
            //   8b783c               | mov                 edi, dword ptr [eax + 0x3c]
            //   037904               | add                 edi, dword ptr [ecx + 4]
            //   8b8610010000         | mov                 eax, dword ptr [esi + 0x110]
            //   8bef                 | mov                 ebp, edi
            //   c1f808               | sar                 eax, 8
            //   896c2414             | mov                 dword ptr [esp + 0x14], ebp
            //   8807                 | mov                 byte ptr [edi], al

        $sequence_8 = { 8b4620 83c408 314500 8b4624 314504 8b4628 314648 }
            // n = 7, score = 200
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   83c408               | add                 esp, 8
            //   314500               | xor                 dword ptr [ebp], eax
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   314504               | xor                 dword ptr [ebp + 4], eax
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   314648               | xor                 dword ptr [esi + 0x48], eax

        $sequence_9 = { eb06 8b55f4 8955f0 b801000000 6bc800 8b55f0 0fbe040a }
            // n = 7, score = 200
            //   eb06                 | jmp                 8
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   b801000000           | mov                 eax, 1
            //   6bc800               | imul                ecx, eax, 0
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   0fbe040a             | movsx               eax, byte ptr [edx + ecx]

    condition:
        7 of them and filesize < 3743744
}