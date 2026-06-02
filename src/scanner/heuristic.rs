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
    ProcessInjection,
    ProcessHollowing,
    ReflectiveLoading,
    Persistence,
    AntiDebug,
    AntiVM,
    Packed,
    Downloader,
    Keylogger,
    CredentialAccess,
    Ransomware,
    NetworkBeaconing,
    PrivilegeEscalation,
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
            score: 15,
        },
    ),
    (
        "WriteProcessMemory",
        ImportRule {
            category: Category::ProcessInjection,
            score: 20,
        },
    ),
    (
        "CreateRemoteThread",
        ImportRule {
            category: Category::ProcessInjection,
            score: 25,
        },
    ),
    (
        "IsDebuggerPresent",
        ImportRule {
            category: Category::AntiDebug,
            score: 10,
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
