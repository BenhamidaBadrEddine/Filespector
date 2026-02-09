rule Suspecious_strings {
    meta :
        description = "The rules used to detect suspecious strings"
        author = "Badr Eddine"
        date = "2026-02-07"
        confidence = "medium"
    strings : 
        //Execution and script commands
        $cmd1 = "cmd.exe" nocase ascii
        $cmd2 = "powershell" nocase ascii
        $cmd5 = "wscript.exe" nocase ascii
        $cmd6 = "cscript.exe" nocase ascii
        $cmd8 = "rundll32.exe" nocase ascii
        $cmd9 = "regsvr32.exe" nocase ascii
        //Persistenca and registry keys
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase ascii
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" nocase ascii
        $reg4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase ascii
        $reg5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase ascii
        $reg6 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnceEx" nocase ascii
        $reg7 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnceEx" nocase ascii
        $reg8 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase ascii
        //Network conections
        $net1 = "ftp.exe" nocase ascii
        $net2 = "curl" nocase ascii
        $net3 = "wget" nocase ascii
        $net4 = "ssh" nocase ascii
        $net5 = "telnet" nocase ascii
        //Powershell commands
        $ps1 = "Invoke-Expression" nocase ascii
        $ps2 = "Invoke-WebRequest" nocase ascii
        $ps3 = "New-Object Net.WebClient" nocase ascii
        $ps4 = "DownloadString" nocase ascii
        $ps5 = "FromBase64String" nocase ascii
        //Encodig and obfuscation
        $enc1 = "base64" nocase ascii
        $enc2 = "xor" nocase ascii
        $enc3 = "shellcode" nocase ascii
    condition : 
        any of them
}