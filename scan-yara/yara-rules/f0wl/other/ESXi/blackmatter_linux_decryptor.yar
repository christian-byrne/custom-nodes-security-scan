import "elf"

rule blackmatter_linux_decryptor : Ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <https://dissectingmalwa.re>"
      description = "Detects BlackMatter Linux Ransomware Version 1.6.0.2 to 1.6.0.4 with ESXI capabilities (Decryptor)"
      reference = "https://github.com/f0wl/configmatter-linux"
      date = "2021-10-16"
      tlp = "WHITE"
      hash = "e48c87a1bb47f60080320167d73f30ca3e6e9964c04ce294c20a451ec1dff425"
   
   strings:
      // Functions
      $func = "bool app::esxi_utils::get_process_list(std::vector<std::basic_string<char> >&)" ascii
      
      // Configuration
      $cfg1 = "disk.dark-size" fullword ascii
      $cfg2 = "disk.white-size" fullword ascii
      $cfg3 = "disk.min-size" fullword ascii
      
      // Logging
      $log1 = "[FW Stopping]" ascii
      $log2 = "[FILE]" ascii
      $log3 = "Removing Self Executable..." ascii
      $log4 = "Another Instance Currently Running..." ascii

      // File name "/tmp/.DBFD055C-9CF2-4BB8-908E-6DA22321BF17"
      $tmpFileName = {44424644C744241430353543C74424182D394346C744241C322D3442C744242042382D39C74424243038452DC744242836444132C744242C32333231C744243042463137}
      
      // Rolling XOR to decrypt the config blob
      $configDecrypt = {4885ff74424929f84983f82074394901f831c94531c90f1f8400000000000fb61084d274190fb6340f4038f274104883c10131f24883f9208810490f44c94883c0014c39c075d7}

      // SHA-1 constant values
      $sha1Constants = {c70701234567c7470489abcdefc74708fedcba98c7470c76543210c74710f0e1d2c3}
   
   condition:
      uint16(0) == 0x457f 
      and filesize < 5000KB
      and elf.number_of_sections > 30
      and for any i in (12..elf.number_of_sections-12):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgDTD")
            )
      and $func
      and 3 of ($cfg*)
      and 3 of ($log*)
      and $tmpFileName
      and $configDecrypt
      and $sha1Constants
}