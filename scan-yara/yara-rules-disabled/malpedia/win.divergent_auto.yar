rule win_divergent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.divergent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.divergent"
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
        $sequence_0 = { 8bc1 880438 40 3d00010000 7cf5 8b450c }
            // n = 6, score = 300
            //   8bc1                 | mov                 eax, ecx
            //   880438               | mov                 byte ptr [eax + edi], al
            //   40                   | inc                 eax
            //   3d00010000           | cmp                 eax, 0x100
            //   7cf5                 | jl                  0xfffffff7
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_1 = { 83c418 85db 0f8537ffffff 5f 5e 68???????? ff15???????? }
            // n = 7, score = 300
            //   83c418               | add                 esp, 0x18
            //   85db                 | test                ebx, ebx
            //   0f8537ffffff         | jne                 0xffffff3d
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_2 = { 3b4510 7518 ff7510 8b4704 ff750c }
            // n = 5, score = 300
            //   3b4510               | cmp                 eax, dword ptr [ebp + 0x10]
            //   7518                 | jne                 0x1a
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_3 = { 85c0 750a 830604 5e 5d e9???????? 33c0 }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   830604               | add                 dword ptr [esi], 4
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { ff15???????? 837e0800 7412 ff7608 ff15???????? ff7608 e8???????? }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   837e0800             | cmp                 dword ptr [esi + 8], 0
            //   7412                 | je                  0x14
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff15????????         |                     
            //   ff7608               | push                dword ptr [esi + 8]
            //   e8????????           |                     

        $sequence_5 = { 3bf1 7421 3bf9 741d 3bc1 7419 c1e204 }
            // n = 7, score = 300
            //   3bf1                 | cmp                 esi, ecx
            //   7421                 | je                  0x23
            //   3bf9                 | cmp                 edi, ecx
            //   741d                 | je                  0x1f
            //   3bc1                 | cmp                 eax, ecx
            //   7419                 | je                  0x1b
            //   c1e204               | shl                 edx, 4

        $sequence_6 = { 85db 0f84da000000 3975f4 0f84d1000000 53 e8???????? 8945e4 }
            // n = 7, score = 300
            //   85db                 | test                ebx, ebx
            //   0f84da000000         | je                  0xe0
            //   3975f4               | cmp                 dword ptr [ebp - 0xc], esi
            //   0f84d1000000         | je                  0xd7
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_7 = { 5d c3 ff25???????? 55 8bec 837d0800 741f }
            // n = 7, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   741f                 | je                  0x21

        $sequence_8 = { e8???????? 8bf8 83c414 85ff 742c 8b463c ff743054 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c414               | add                 esp, 0x14
            //   85ff                 | test                edi, edi
            //   742c                 | je                  0x2e
            //   8b463c               | mov                 eax, dword ptr [esi + 0x3c]
            //   ff743054             | push                dword ptr [eax + esi + 0x54]

        $sequence_9 = { 0fb6f1 0fb6ca 0fb60406 034510 03c8 81e1ff000080 7908 }
            // n = 7, score = 300
            //   0fb6f1               | movzx               esi, cl
            //   0fb6ca               | movzx               ecx, dl
            //   0fb60406             | movzx               eax, byte ptr [esi + eax]
            //   034510               | add                 eax, dword ptr [ebp + 0x10]
            //   03c8                 | add                 ecx, eax
            //   81e1ff000080         | and                 ecx, 0x800000ff
            //   7908                 | jns                 0xa

    condition:
        7 of them and filesize < 212992
}