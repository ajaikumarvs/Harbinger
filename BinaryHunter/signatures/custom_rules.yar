rule WindowsSuspiciousExe {
    meta:
        description = "Detects suspicious Windows executables"
        author = "Security Analyst"
        date = "2024-01"
        severity = "high"
    
    strings:
        // Process manipulation
        $proc1 = "CreateRemoteThread" ascii wide
        $proc2 = "VirtualAllocEx" ascii wide
        $proc3 = "WriteProcessMemory" ascii wide
        $proc4 = "ReadProcessMemory" ascii wide
        
        // Suspicious imports
        $imp1 = "LoadLibraryA" ascii wide
        $imp2 = "GetProcAddress" ascii wide
        $imp3 = "ShellExecute" ascii wide
        
        // Command execution
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "wscript" ascii wide nocase
        
        // Registry manipulation
        $reg1 = "RegCreateKey" ascii wide
        $reg2 = "RegSetValue" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and // MZ header
        (
            2 of ($proc*) or
            2 of ($imp*) or
            any of ($cmd*) or
            all of ($reg*)
        )
}

rule SuspiciousScriptContent {
    meta:
        description = "Detects suspicious script content"
        author = "Security Analyst"
        date = "2024-01"
        severity = "medium"
    
    strings:
        // Encoded commands
        $enc1 = "base64" ascii wide nocase
        $enc2 = "-enc" ascii wide
        $enc3 = "FromBase64String" ascii wide
        
        // Suspicious PowerShell commands
        $ps1 = "Invoke-Expression" ascii wide nocase
        $ps2 = "IEX" ascii wide
        $ps3 = "Invoke-WebRequest" ascii wide nocase
        $ps4 = "wget" ascii wide
        
        // Obfuscation techniques
        $obf1 = "char" ascii wide
        $obf2 = "join" ascii wide
        $obf3 = "`+`" ascii
        
    condition:
        (2 of ($enc*)) or
        (2 of ($ps*)) or
        (2 of ($obf*))
}

rule RansomwareIndicators {
    meta:
        description = "Detects common ransomware indicators"
        author = "Security Analyst"
        date = "2024-01"
        severity = "critical"
    
    strings:
        // File operations
        $op1 = "CryptoAPI" ascii wide
        $op2 = "DeleteBackupFiles" ascii wide
        $op3 = "EncryptFiles" ascii wide
        
        // Ransom notes
        $note1 = "ransom" ascii wide nocase
        $note2 = "encrypted" ascii wide nocase
        $note3 = "bitcoin" ascii wide nocase
        $note4 = "decrypt" ascii wide nocase
        
        // File extensions
        $ext1 = ".locked" ascii wide
        $ext2 = ".crypt" ascii wide
        $ext3 = ".encrypted" ascii wide
        
    condition:
        (2 of ($op*)) or
        (2 of ($note*)) or
        (any of ($ext*))
}

rule NetworkExfiltration {
    meta:
        description = "Detects potential data exfiltration behavior"
        author = "Security Analyst"
        date = "2024-01"
        severity = "high"
    
    strings:
        // Network connections
        $net1 = "socket" ascii wide
        $net2 = "connect" ascii wide
        $net3 = "WSAStartup" ascii wide
        
        // Common protocols
        $proto1 = "http://" ascii wide nocase
        $proto2 = "https://" ascii wide nocase
        $proto3 = "ftp://" ascii wide nocase
        
        // Data packaging
        $data1 = "zip" ascii wide
        $data2 = "rar" ascii wide
        $data3 = "compress" ascii wide
        
    condition:
        (2 of ($net*)) and
        (any of ($proto*) or any of ($data*))
}

rule KeyloggerBehavior {
    meta:
        description = "Detects potential keylogger functionality"
        author = "Security Analyst"
        date = "2024-01"
        severity = "high"
    
    strings:
        // Keyboard hooks
        $hook1 = "SetWindowsHookEx" ascii wide
        $hook2 = "GetAsyncKeyState" ascii wide
        $hook3 = "GetKeyboardState" ascii wide
        
        // Log file operations
        $log1 = "keylog" ascii wide nocase
        $log2 = ".log" ascii wide
        $log3 = "log.txt" ascii wide
        
    condition:
        any of ($hook*) and any of ($log*)
}

rule AntiAnalysisTechniques {
    meta:
        description = "Detects anti-analysis and evasion techniques"
        author = "Security Analyst"
        date = "2024-01"
        severity = "high"
    
    strings:
        // Anti-debug
        $debug1 = "IsDebuggerPresent" ascii wide
        $debug2 = "CheckRemoteDebuggerPresent" ascii wide
        $debug3 = "OutputDebugString" ascii wide
        
        // Anti-VM
        $vm1 = "vmware" ascii wide nocase
        $vm2 = "virtualbox" ascii wide nocase
        $vm3 = "vbox" ascii wide nocase
        
        // Timing checks
        $time1 = "GetTickCount" ascii wide
        $time2 = "QueryPerformanceCounter" ascii wide
        $time3 = "timeGetTime" ascii wide
        
    condition:
        (any of ($debug*)) or
        (any of ($vm*)) or
        (2 of ($time*))
}
