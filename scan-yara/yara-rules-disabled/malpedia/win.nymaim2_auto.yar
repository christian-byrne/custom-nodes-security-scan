rule win_nymaim2_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nymaim2."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nymaim2"
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
        $sequence_0 = { e8???????? 8d4de4 c645fc45 e8???????? 8d4de0 c645fc05 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   c645fc45             | mov                 byte ptr [ebp - 4], 0x45
            //   e8????????           |                     
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   e8????????           |                     

        $sequence_1 = { e8???????? 83ec20 56 33f6 3935???????? 7546 68da010000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83ec20               | sub                 esp, 0x20
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   3935????????         |                     
            //   7546                 | jne                 0x48
            //   68da010000           | push                0x1da

        $sequence_2 = { 50 8d45f0 50 e8???????? e8???????? 834dfcff 8d4df0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8d4df0               | lea                 ecx, [ebp - 0x10]

        $sequence_3 = { e8???????? 8b7510 59 59 8b16 50 8bce }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi

        $sequence_4 = { c645fc46 e8???????? 8d4de4 c645fc1b e8???????? 8d4ddc e8???????? }
            // n = 7, score = 200
            //   c645fc46             | mov                 byte ptr [ebp - 4], 0x46
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   c645fc1b             | mov                 byte ptr [ebp - 4], 0x1b
            //   e8????????           |                     
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     

        $sequence_5 = { 8d45d4 8bce 50 c645fc01 e8???????? 8d45c0 8d4dd4 }
            // n = 7, score = 200
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]

        $sequence_6 = { 56 8bcf c645fc09 ff5008 51 8d4604 8bcc }
            // n = 7, score = 200
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   c645fc09             | mov                 byte ptr [ebp - 4], 9
            //   ff5008               | call                dword ptr [eax + 8]
            //   51                   | push                ecx
            //   8d4604               | lea                 eax, [esi + 4]
            //   8bcc                 | mov                 ecx, esp

        $sequence_7 = { 8d4df0 e9???????? 8d4dc0 e9???????? 8d4dec e9???????? 8b45e8 }
            // n = 7, score = 200
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   e9????????           |                     
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e9????????           |                     
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   e9????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_8 = { 8d86640c0000 8bd9 03c9 c1eb1f 0bd9 c746040e000000 33da }
            // n = 7, score = 200
            //   8d86640c0000         | lea                 eax, [esi + 0xc64]
            //   8bd9                 | mov                 ebx, ecx
            //   03c9                 | add                 ecx, ecx
            //   c1eb1f               | shr                 ebx, 0x1f
            //   0bd9                 | or                  ebx, ecx
            //   c746040e000000       | mov                 dword ptr [esi + 4], 0xe
            //   33da                 | xor                 ebx, edx

        $sequence_9 = { 8bc8 c645fc03 e8???????? 51 8bcc 8965ec 50 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   e8????????           |                     
            //   51                   | push                ecx
            //   8bcc                 | mov                 ecx, esp
            //   8965ec               | mov                 dword ptr [ebp - 0x14], esp
            //   50                   | push                eax

    condition:
        7 of them and filesize < 753664
}