rule win_nabucur_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nabucur."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nabucur"
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
        $sequence_0 = { 48 49 85c0 75fa }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   49                   | dec                 ecx
            //   85c0                 | test                eax, eax
            //   75fa                 | jne                 0xfffffffc

        $sequence_1 = { 48 5f 894500 5d }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   5f                   | pop                 edi
            //   894500               | mov                 dword ptr [ebp], eax
            //   5d                   | pop                 ebp

        $sequence_2 = { 48 83e908 85c0 75f0 57 }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   83e908               | sub                 ecx, 8
            //   85c0                 | test                eax, eax
            //   75f0                 | jne                 0xfffffff2
            //   57                   | push                edi

        $sequence_3 = { 48 83e904 85c0 7ff3 8bf0 8b442448 }
            // n = 6, score = 200
            //   48                   | dec                 eax
            //   83e904               | sub                 ecx, 4
            //   85c0                 | test                eax, eax
            //   7ff3                 | jg                  0xfffffff5
            //   8bf0                 | mov                 esi, eax
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]

        $sequence_4 = { 48 83f801 89442418 0f8f15ffffff }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   83f801               | cmp                 eax, 1
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   0f8f15ffffff         | jg                  0xffffff1b

        $sequence_5 = { 33ff 33f6 4a c744244001000000 }
            // n = 4, score = 200
            //   33ff                 | xor                 edi, edi
            //   33f6                 | xor                 esi, esi
            //   4a                   | dec                 edx
            //   c744244001000000     | mov                 dword ptr [esp + 0x40], 1

        $sequence_6 = { 009eaa030000 0fb686aa030000 57 83f80a 0f876d010000 }
            // n = 5, score = 200
            //   009eaa030000         | add                 byte ptr [esi + 0x3aa], bl
            //   0fb686aa030000       | movzx               eax, byte ptr [esi + 0x3aa]
            //   57                   | push                edi
            //   83f80a               | cmp                 eax, 0xa
            //   0f876d010000         | ja                  0x173

        $sequence_7 = { 48 8906 8d442410 50 }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   8906                 | mov                 dword ptr [esi], eax
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax

        $sequence_8 = { ba86a33ffb 83e904 ba575a2bfd eb69 83f901 7519 }
            // n = 6, score = 100
            //   ba86a33ffb           | mov                 edx, 0xfb3fa386
            //   83e904               | sub                 ecx, 4
            //   ba575a2bfd           | mov                 edx, 0xfd2b5a57
            //   eb69                 | jmp                 0x6b
            //   83f901               | cmp                 ecx, 1
            //   7519                 | jne                 0x1b

        $sequence_9 = { 3f 71e3 0c42 869576f1896a 86f6 }
            // n = 5, score = 100
            //   3f                   | aas                 
            //   71e3                 | jno                 0xffffffe5
            //   0c42                 | or                  al, 0x42
            //   869576f1896a         | xchg                byte ptr [ebp + 0x6a89f176], dl
            //   86f6                 | xchg                dh, dh

        $sequence_10 = { 732e 5c 54 7346 b654 8c534c }
            // n = 6, score = 100
            //   732e                 | jae                 0x30
            //   5c                   | pop                 esp
            //   54                   | push                esp
            //   7346                 | jae                 0x48
            //   b654                 | mov                 dh, 0x54
            //   8c534c               | mov                 word ptr [ebx + 0x4c], ss

        $sequence_11 = { 141b 46 ec 54 732e }
            // n = 5, score = 100
            //   141b                 | adc                 al, 0x1b
            //   46                   | inc                 esi
            //   ec                   | in                  al, dx
            //   54                   | push                esp
            //   732e                 | jae                 0x30

        $sequence_12 = { 01e4 01f4 1481 0491 00850cf41196 }
            // n = 5, score = 100
            //   01e4                 | add                 esp, esp
            //   01f4                 | add                 esp, esi
            //   1481                 | adc                 al, 0x81
            //   0491                 | add                 al, 0x91
            //   00850cf41196         | add                 byte ptr [ebp - 0x69ee0bf4], al

        $sequence_13 = { ff75f8 ff35???????? ff15???????? 8b7520 8b45e4 }
            // n = 5, score = 100
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8b7520               | mov                 esi, dword ptr [ebp + 0x20]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_14 = { 8b4608 50 ff15???????? 61 eb11 }
            // n = 5, score = 100
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   61                   | popal               
            //   eb11                 | jmp                 0x13

        $sequence_15 = { 06 e409 9a1496099a1581 0d911c9060 9d 01e4 }
            // n = 6, score = 100
            //   06                   | push                es
            //   e409                 | in                  al, 9
            //   9a1496099a1581       | lcall               0x8115:0x9a099614
            //   0d911c9060           | or                  eax, 0x60901c91
            //   9d                   | popfd               
            //   01e4                 | add                 esp, esp

    condition:
        7 of them and filesize < 1949696
}