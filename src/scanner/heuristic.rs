use goblin::Object;

pub struct FileTypeInfo {
    pub extension: String,
    pub mime_type: String,
}

pub struct PeInfo {
    pub kind:     String,
    pub arch:     String,
    pub sections: Vec<String>,
    pub imports:  Vec<String>,
}

#[derive(Debug)]
pub struct ScoreSystem {
    pub score: u32,
    pub reasons: Vec<String>,
    pub categories: Vec<Category>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Category {

    // function imports

    ProcessInjection,
    ProcessHollowing,
    ReflectiveLoading,
    Persistence,
    AntiDebug,
    Packed,
    Downloader,
    Keylogger,
    CredentialAccess,
    Ransomware,
    Networking_C2,
    PrivilegeEscalation,
    Timing,
    Discovery,
    File_Manipulation,

    // string imports

    ShellExecution,
    PowerShellExecution,
    EncodedPowerShell,
    ScriptExecution,
    LOLBinExecution,
    LOLBinDownload,
    RegistryPersistence,
    ServicePersistence,
    TempDirectoryUsage,
    AppDataUsage,
    AccountDiscovery,
    PrivilegeDiscovery,
    NetworkActivity,
    UnixShellReference,
    DownloadActivity,
    RansomPayment,
    Tor,
    VMDetection,
    SandboxDetection,
}

pub struct ImportRule {
    pub category: Category,
    pub score: u32,
}

const SUSPICIOUS_IMPORTS: &[(&str, ImportRule)] = &[
    (
        "VirtualAlloc",
        ImportRule {
            category: Category::ProcessInjection,
            score: 1,
        },
    ),
    (
        "VirtualAllocEx",
        ImportRule {
            category: Category::ProcessInjection,
            score: 2,
        }
    ),
    (
        "WriteProcessMemory",
        ImportRule {
            category: Category::ProcessInjection,
            score: 3,
        },
    ),
    (
        "CreateRemoteThread",
        ImportRule {
            category: Category::ProcessInjection,
            score: 3,
        },
    ),
    (
        "NtCreateThreadEx",
        ImportRuleFunc {
            category: Category::ProcessInjection,
            score: 3,
        },
    ),
    (
        "QueueUserAPC",
        ImportRule {
            category: Category::ProcessInjection,
            score: 2,
        },
    ),
    (
        "SetThreadContext",
        ImportRule {
            category: Category::ProcessInjection,
            score: 2,
        },
    ),
    (
        "OpenProcess",
        ImportRule {
            category: Category::ProcessInjection,
            score: 1,
        },
    ),
    (
        "NtUnmapViewOfSection",
        ImportRule {
            category: Category::ProcessHollowing,
            score: 3,
        },
    ),
    (
        "IsDebuggerPresent",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "CheckRemoteDebuggerPresent",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "NtQueryInformationProcess",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "GetTickCount",
        ImportRule {
            category: Category::Timing,
            score: 1,
        },
    ),
    (
        "Sleep",
        ImportRule {
            category: Category::Timing,
            score: 1,
        },
    ),
    (
        "NtDelayExecution",
        ImportRule {
            category: Category::Timing,
            score: 2,
        },
    ),
    (
        "AdjustTokenPrivileges",
        ImportRule {
            category: Category::PrivilegeEscalation,
            score: 2,
        },
    ),
    (
        "OpenProcessToken",
        ImportRule {
            category: Category::PrivilegeEscalation,
            score: 1,
        },
    ),
    (
        "LookupPrivilegeValue",
        ImportRule {
            category: Category::PrivilegeEscalation,
            score: 1,
        },
    ),
    (
        "RegSetValueExA",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),
    (
        "RegSetValueExW",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),
    (
        "RegCreateKeyExA",
        ImportRule {
            category: Category::Persistence,
            score: 1,
        },
    ),
    (
        "RegCreateKeyExW",
        ImportRule {
            category: Category::Persistence,
            score: 1,
        },
    ),
    (
        "SHSetValue",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),
    (
        "WSAStartup",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "InternetOpenA",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "InternetOpenW",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "HttpSendRequestA",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "HttpSendRequestW",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "WinHttpOpen",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "connect",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "SetWindowsHookExA",
        ImportRule {
            category: Category::Keylogger,
            score: 3,
        },
    ),
    (
        "SetWindowsHookExW",
        ImportRule {
            category: Category::Keylogger,
            score: 3,
        },
    ),
    (
        "GetAsyncKeyState",
        ImportRule {
            category: Category::Keylogger,
            score: 2,
        },
    ),
    (
        "GetKeyboardState",
        ImportRule {
            category: Category::Keylogger,
            score: 3,
        },
    ),
    (
        "GetSystemInfo",
        ImportRule {
            category: Category::Discovery,
            score: 1,
        },
    ),
    (
        "GetComputerNameA",
        ImportRule {
            category: Category::Discovery,
            score: 1,
        },
    ),
    (
        "GetComputerNameW",
        ImportRule {
            category: Category::Discovery,
            score: 1,
        },
    ),
    (
        "EnumProcesses",
        ImportRule {
            category: Category::Discovery,
            score: 2,
        },
    ),
    (
        "CreateToolhelp32Snapshot",
        ImportRule {
            category: Category::Discovery,
            score: 1,
        },
    ),
    (
        "MoveFileExA",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "MoveFileExW",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "DeleteFileA",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "DeleteFileW",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "CryptEncrypt",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),
    (
        "CryptGenKey",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),
    (
        "BCryptEncrypt",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),
];

const SUSPICIOUS_STRINGS: &[(&str, ImportRule)] = &[
    // Execution via shell
    (
        "cmd.exe /c",
        ImportRule {
            category: Category::ShellExecution,
            score: 2,
        },
    ),
    (
        "cmd /c",
        ImportRule {
            category: Category::ShellExecution,
            score: 2,
        },
    ),
    (
        "powershell -e",
        ImportRule {
            category: Category::EncodedPowerShell,
            score: 3,
        },
    ),
    (
        "powershell -enc",
        ImportRule {
            category: Category::EncodedPowerShell,
            score: 3,
        },
    ),
    (
        "powershell -nop",
        ImportRule {
            category: Category::PowerShellExecution,
            score: 2,
        },
    ),
    (
        "powershell -w hidden",
        ImportRule {
            category: Category::PowerShellExecution,
            score: 2,
        },
    ),
    (
        "wscript.exe",
        ImportRule {
            category: Category::ScriptExecution,
            score: 2,
        },
    ),
    (
        "cscript.exe",
        ImportRule {
            category: Category::ScriptExecution,
            score: 2,
        },
    ),
    (
        "mshta.exe",
        ImportRule {
            category: Category::LOLBinExecution,
            score: 3,
        },
    ),
    (
        "rundll32.exe",
        ImportRule {
            category: Category::LOLBinExecution,
            score: 2,
        },
    ),
    (
        "regsvr32.exe",
        ImportRule {
            category: Category::LOLBinExecution,
            score: 2,
        },
    ),
    (
        "certutil -decode",
        ImportRule {
            category: Category::LOLBinExecution,
            score: 3,
        },
    ),
    (
        "bitsadmin /transfer",
        ImportRule {
            category: Category::Downloader,
            score: 3,
        },
    ),

    // Persistence
    (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),
    (
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),
    (
        "SYSTEM\\CurrentControlSet\\Services",
        ImportRule {
            category: Category::Persistence,
            score: 2,
        },
    ),

    // Suspicious paths
    (
        "%TEMP%",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "\\AppData\\Roaming",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),
    (
        "\\AppData\\Local\\Temp",
        ImportRule {
            category: Category::File_Manipulation,
            score: 1,
        },
    ),

    // Credential / privilege strings
    (
        "SeDebugPrivilege",
        ImportRule {
            category: Category::PrivilegeEscalation,
            score: 2,
        },
    ),
    (
        "net user",
        ImportRule {
            category: Category::Discovery,
            score: 2,
        },
    ),
    (
        "net localgroup administrators",
        ImportRule {
            category: Category::PrivilegeEscalation,
            score: 3,
        },
    ),

    // Network indicators
    (
        "http://",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "https://",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "ftp://",
        ImportRule {
            category: Category::Networking_C2,
            score: 1,
        },
    ),
    (
        "/bin/sh",
        ImportRule {
            category: Category::Downloader,
            score: 2,
        },
    ),
    (
        "wget ",
        ImportRule {
            category: Category::Downloader,
            score: 2,
        },
    ),
    (
        "curl ",
        ImportRule {
            category: Category::Downloader,
            score: 2,
        },
    ),

    // Ransomware
    (
        "YOUR FILES HAVE BEEN ENCRYPTED",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),
    (
        "bitcoin",
        ImportRule {
            category: Category::Ransomware,
            score: 2,
        },
    ),
    (
        ".onion",
        ImportRule {
            category: Category::Networking_C2,
            score: 3,
        },
    ),
    (
        "CryptoLocker",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),
    (
        "WannaCry",
        ImportRule {
            category: Category::Ransomware,
            score: 3,
        },
    ),

    // Evasion / anti-analysis
    (
        "IsDebuggerPresent",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "VirtualBox",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "VMware",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "VBOX",
        ImportRule {
            category: Category::AntiDebug,
            score: 2,
        },
    ),
    (
        "SandboxEnvironment",
        ImportRule {
            category: Category::AntiDebug,
            score: 3,
        },
    ),

    // Injection strings
    (
        "VirtualAllocEx",
        ImportRule {
            category: Category::ProcessInjection,
            score: 2,
        },
    ),
    (
        "CreateRemoteThread",
        ImportRule {
            category: Category::ProcessInjection,
            score: 2,
        },
    ),
];

//  File Type Detection

pub fn detect_mime(path: &str) -> Option<FileTypeInfo> {
    let bytes = std::fs::read(path).ok()?;

    if let Ok(obj) = Object::parse(&bytes) {
        let (extension, mime_type) = match obj {
            Object::PE(pe) => {
                if pe.is_lib { ("dll", "application/x-dosexec") }
                else         { ("exe", "application/x-dosexec") }
            }
            Object::Elf(_)  => ("elf", "application/x-elf"),
            Object::Mach(_) => ("macho", "application/x-mach-binary"),
            _               => ("", ""),
        };
        if !extension.is_empty() {
            return Some(FileTypeInfo {
                extension: extension.to_string(),
                mime_type: mime_type.to_string(),
            });
        }
    }

    let mime = tree_magic_mini::from_u8(&bytes);
    Some(FileTypeInfo {
        extension: file_type(mime).to_string(),
        mime_type: mime.to_string(),
    })
}

fn file_type(mime: &str) -> &str {
    match mime {
        "application/pdf"     => "pdf",
        "application/zip"     => "zip",
        "application/x-rar"   => "rar",
        "text/x-python"       => "py",
        "text/x-shellscript"  => "sh",
        "text/html"           => "html",
        "text/plain"          => "txt",
        "image/png"           => "png",
        "image/jpeg"          => "jpg",
        _                     => "unknown",
    }
}

pub fn extract_pe(path: &str) -> Option<PeInfo> {
    let bytes = std::fs::read(path).ok()?;
    let pe = match Object::parse(&bytes).ok()? {
        Object::PE(pe) => pe,
        _              => return None,
    };

    let kind = if pe.is_lib { "DLL" } else { "EXE" }.to_string();

    let arch = match pe.header.coff_header.machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        _      => "Unknown",
    }.to_string();

    let sections = pe.sections.iter()
        .map(|s| std::str::from_utf8(&s.name)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string())
        .collect();

    let imports = pe.imports.iter()
        .map(|i| i.dll.to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    Some(PeInfo { kind, arch, sections, imports })
}

pub fn display(path: &str) {
    println!("\n=== File Info ===");

    match detect_mime(path) {
        Some(info) => println!("Type: {} ({})", info.extension, info.mime_type),
        None       => println!("Type: Unknown"),
    }

    if let Some(pe) = extract_pe(path) {
        println!("Kind: {} | Arch: {}", pe.kind, pe.arch);
        println!("Sections: {}", pe.sections.join(", "));
        println!("Imports:  {}", pe.imports.join(", "));
    }
}

/*
 Add extraction and matching the strings and functions to a file.
Apply total count score of a file.
 
 */
