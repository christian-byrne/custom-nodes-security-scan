rule win_crimson_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2018-11-23"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crimson"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using yara-signator.
     * The code and documentation / approach will be published in the near future here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */

    strings:
        $sequence_0 = { 3bdc df141a 94 b41f }
            // n = 4, score = 1000
            //   3bdc                 | cmp                 ebx, esp
            //   df141a               | fist                word ptr [edx + ebx]
            //   94                   | xchg                eax, esp
            //   b41f                 | mov                 ah, 0x1f

        $sequence_1 = { b41f 214008 39492d 38b9cbd1d3fe }
            // n = 4, score = 1000
            //   b41f                 | mov                 ah, 0x1f
            //   214008               | and                 dword ptr [eax + 8], eax
            //   39492d               | cmp                 dword ptr [ecx + 0x2d], ecx
            //   38b9cbd1d3fe         | cmp                 byte ptr [ecx - 0x12c2e35], bh

        $sequence_2 = { 214008 39492d 38b9cbd1d3fe c81f9e56 }
            // n = 4, score = 1000
            //   214008               | and                 dword ptr [eax + 8], eax
            //   39492d               | cmp                 dword ptr [ecx + 0x2d], ecx
            //   38b9cbd1d3fe         | cmp                 byte ptr [ecx - 0x12c2e35], bh
            //   c81f9e56             | enter               -0x61e1, 0x56

        $sequence_3 = { 55 35fdfbdfff beaed3e886 0800 }
            // n = 4, score = 1000
            //   55                   | push                ebp
            //   35fdfbdfff           | xor                 eax, 0xffdffbfd
            //   beaed3e886           | mov                 esi, 0x86e8d3ae
            //   0800                 | or                  byte ptr [eax], al

        $sequence_4 = { df141a 94 b41f 214008 }
            // n = 4, score = 1000
            //   df141a               | fist                word ptr [edx + ebx]
            //   94                   | xchg                eax, esp
            //   b41f                 | mov                 ah, 0x1f
            //   214008               | and                 dword ptr [eax + 8], eax

        $sequence_5 = { 307362 c1096b bbf9910d38 5c }
            // n = 4, score = 1000
            //   307362               | xor                 byte ptr [ebx + 0x62], dh
            //   c1096b               | ror                 dword ptr [ecx], 0x6b
            //   bbf9910d38           | mov                 ebx, 0x380d91f9
            //   5c                   | pop                 esp

        $sequence_6 = { bbf9910d38 5c d38aa4973fe2 3bdc }
            // n = 4, score = 1000
            //   bbf9910d38           | mov                 ebx, 0x380d91f9
            //   5c                   | pop                 esp
            //   d38aa4973fe2         | ror                 dword ptr [edx - 0x1dc0685c], cl
            //   3bdc                 | cmp                 ebx, esp

        $sequence_7 = { c1096b bbf9910d38 5c d38aa4973fe2 }
            // n = 4, score = 1000
            //   c1096b               | ror                 dword ptr [ecx], 0x6b
            //   bbf9910d38           | mov                 ebx, 0x380d91f9
            //   5c                   | pop                 esp
            //   d38aa4973fe2         | ror                 dword ptr [edx - 0x1dc0685c], cl

        $sequence_8 = { 94 b41f 214008 39492d }
            // n = 4, score = 1000
            //   94                   | xchg                eax, esp
            //   b41f                 | mov                 ah, 0x1f
            //   214008               | and                 dword ptr [eax + 8], eax
            //   39492d               | cmp                 dword ptr [ecx + 0x2d], ecx

        $sequence_9 = { 5c d38aa4973fe2 3bdc df141a }
            // n = 4, score = 1000
            //   5c                   | pop                 esp
            //   d38aa4973fe2         | ror                 dword ptr [edx - 0x1dc0685c], cl
            //   3bdc                 | cmp                 ebx, esp
            //   df141a               | fist                word ptr [edx + ebx]

    condition:
        7 of them
}