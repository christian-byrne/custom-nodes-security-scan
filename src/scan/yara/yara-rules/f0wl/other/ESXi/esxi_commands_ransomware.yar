rule esxi_commands_ransomware {
   
   meta:
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      description = "Detects commands issued by Ransomware to interact with ESXi VMs"
      date = "2021-12-20"
      tlp = "WHITE"
      
      // AvosLocker
      hash0 = "e9a7b43acdddc3d2101995a2e2072381449054a7d8d381e6dc6ed64153c9c96a"
      // BlackCat
      hash1 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"
      // BlackMatter 
      hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
      // HelloKitty  
      hash3 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
      // Hive
      hash4 = "822d89e7917d41a90f5f65bee75cad31fe13995e43f47ea9ea536862884efc25"
      // REvil
      hash5 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"

   strings:
      $keyword0 = "esxi" ascii nocase
      $keyword1 = "vm" ascii nocase
      $keyword2 = "process" ascii nocase
      $keyword3 = "kill" ascii nocase
      $keyword4 = "list" ascii nocase
      $keyword5 = "stop" ascii nocase
     
      // observed in: BlackMatter
      $keyword6 = "firewall" ascii nocase

      // VMware commandline tools
      $command0 = "esxcli" ascii
      $command1 = "esxcfg" ascii
      $command2 = "vicfg" ascii
      $command3 = "vmware-cmd" ascii
      $command4 = "vim-cmd" ascii

      // observed in: Hive, Python ESXi Ransomware, BlackCat
      $command5 = "vmsvc/getallvms" ascii
      $command6 = "vmsvc/power.off" ascii

      // observed in: BlackCat
      $command7 = "vmsvc/snapshot.removeall" ascii
      
      // observed in: BlackMatter, AvosLocker, REvil
      $argument0 = "--type=force" ascii
      $argument1 = "--world-id=" ascii

      // observed in: AvosLocker, Revil
      $argument2 = "--formatter=csv" ascii
      $argument3 = "--format-param=fields==\"WorldID,DisplayName\"" ascii
      
      // observed in: HelloKitty
      $argument4 = "-t=soft" ascii
      $argument5 = "-t=hard" ascii
      $argument6 = "-t=force" ascii
    
      $path0 = "/vmfs"

      // common VMware related file extensions
      $extension0 = "vmx"
      $extension1 = "vmdk"
      $extension2 = "vmsd"
      $extension3 = "vmsn"
      $extension5 = "vmem"
      $extension6 = "vswp"

   condition:
      uint16(0) == 0x457F 
      and filesize < 10MB
      and any of ($keyword*)
      and any of ($command*)
      and (any of ($argument*) or (any of ($path*)) or (any of ($extension*)))
} 