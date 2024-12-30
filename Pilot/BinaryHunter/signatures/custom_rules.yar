rule WindowsSuspiciousExe {
    meta:
        description = "Detects highly suspicious Windows executables"
        severity = "high"
    
    strings:
        $mz = "MZ"
        
        $proc1 = "CreateRemoteThread" ascii wide
        $proc2 = "VirtualAllocEx" ascii wide
        $proc3 = "WriteProcessMemory" ascii wide
        $proc4 = "ReadProcessMemory" ascii wide
        
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        
    condition:
        $mz at 0 and 
        (
            3 of ($proc*) or
            all of ($cmd*)
        )
}

rule RansomwareIndicators {
    meta:
        description = "Detects common ransomware indicators"
        severity = "critical"
    
    strings:
        $op1 = "CryptoAPI" ascii wide
        $op2 = "DeleteBackupFiles" ascii wide
        $op3 = "EncryptFiles" ascii wide
        
        $note1 = "ransom" ascii wide nocase
        $note2 = "encrypted" ascii wide nocase
        $note3 = "decrypt" ascii wide nocase
        
    condition:
        2 of ($op*) and 2 of ($note*)
}

rule SuspiciousNetworkBehavior {
    meta:
        description = "Detects suspicious network and data exfiltration behavior"
        severity = "high"
    
    strings:
        $net1 = "socket" ascii wide
        $net2 = "connect" ascii wide
        $net3 = "WSAStartup" ascii wide
        
        $proto1 = "http://" ascii wide nocase
        $proto2 = "https://" ascii wide nocase
        $proto3 = "ftp://" ascii wide nocase
        
        $data1 = "zip" ascii wide
        $data2 = "rar" ascii wide
        $data3 = "compress" ascii wide
        
    condition:
        2 of ($net*) and 
        (any of ($proto*) or 2 of ($data*))
}

rule AntiAnalysisTechniques {
    meta:
        description = "Detects anti-analysis and evasion techniques"
        severity = "medium" 
    
    strings:
        $debug1 = "IsDebuggerPresent" ascii wide
        $debug2 = "CheckRemoteDebuggerPresent" ascii wide
        
        $vm1 = "vmware" ascii wide nocase
        $vm2 = "virtualbox" ascii wide nocase
        $vm3 = "vbox" ascii wide nocase
        
    condition:
        2 of ($debug*) or 2 of ($vm*)
}