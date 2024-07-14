import "elf"

rule blackmatter_linux_encryptor : Ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <https://dissectingmalwa.re>"
      description = "Detects BlackMatter Linux Ransomware Version 1.6.0.2 to 1.6.0.4 with ESXI capabilities (Encryptor)"
      reference = "https://github.com/f0wl/configmatter-linux"
      date = "2021-10-16"
      tlp = "WHITE"
      hash1 = "6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502"
      hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
      hash3 = "1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f"
   
   strings:
      // Functions
      $func1 = "bool app::esxi_utils::get_process_list(std::vector<std::basic_string<char> >&)" ascii
      $func2 = "bool app::master_proc::process_file_encryption(std::shared_ptr<app::setup_impl>, size_t&, size_t&, size_t&)" ascii
      $func3 = "bool app::file_encrypter::process_file(const string&)" ascii
      
      // Command&Control
      $cc1 = "host_hostname" fullword ascii
      $cc2 = "host_os" fullword ascii
      $cc3 = "bot_version" fullword ascii
      $cc4 = "bot_company" fullword ascii
      $cc5 = "stat_all_files" fullword ascii
      $cc6 = "stat_not_encrypted" fullword ascii
      
      // Configuration
      $cfg1 = "landing.key" fullword ascii
      $cfg2 = "landing.bot-id" fullword ascii
      $cfg3 = "kill-vm.ignore-list" fullword ascii
      $cfg4 = "kill-process.list" fullword ascii
      $cfg5 = "disk.dark-size" fullword ascii
      $cfg6 = "disk.white-size" fullword ascii
      $cfg7 = "disk.min-size" fullword ascii
      
      // Logging
      $log1 = "[FW Stopping]" ascii
      $log2 = "[WEB]" ascii
      $log3 = "[FILE]" ascii
      $log4 = "Removing Self Executable..." ascii
      $log5 = "Another Instance Currently Running..." ascii

      // File name "/tmp/.DBFD055C-9CF2-4BB8-908E-6DA22321BF17"
      $tmpFileName = {44424644C744241430353543C74424182D394346C744241C322D3442C744242042382D39C74424243038452DC744242836444132C744242C32333231C744243042463137}
      
      // Rolling XOR to decrypt the config blob
      $configDecrypt = {4885ff74424929f84983f82074394901f831c94531c90f1f8400000000000fb61084d274190fb6340f4038f274104883c10131f24883f9208810490f44c94883c0014c39c075d7}

      // SHA-1 constant values
      $sha1Constants = {c70701234567c7470489abcdefc74708fedcba98c7470c76543210c74710f0e1d2c3}

      // cpuid syscall
      $cpuidCall = {81fb47656e7575ceb8010000000fa281e10000004074bf48c74500000000005b5d415cc3}

      // Timestamp calculation
      $gettimeofday = {e86f30ffff488b0424488b4c240848bacff753e3a59bc420488943084889c848c1f93f48f7ea48c1fa074829ca668953104883c4185b5d415c415d415e415fc3}
   
   condition:
      uint16(0) == 0x457f 
      and filesize < 5000KB
      and elf.number_of_sections > 30
      and for any i in (12..elf.number_of_sections-12):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgETD")
            )
      and any of ($func*)
      and 3 of ($cc*)
      and 3 of ($cfg*)
      and 3 of ($log*)
      and $tmpFileName
      and $configDecrypt
      and $sha1Constants
      and $cpuidCall
      and $gettimeofday
}