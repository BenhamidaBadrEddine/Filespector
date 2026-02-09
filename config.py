# Risk Levels
BENIGN = "Benign"
SUSPICIOUS = "Suspicious"
MALICIOUS = "Malicious"


SUSPICIOUS_FILE_EXTENSIONS = [
    ".exe", ".pif", ".application", ".com", ".scr",  # Executable Files
    ".msi", ".cab", ".msp",                         # Installer Files
    ".bat", ".cmd",                                 # Batch Files
    ".vbs", ".vbe",                                 # VBScript Files
    ".js", ".jse",                                  # JavaScript Files
    ".ws", ".wsc", ".wsh", ".wsf",                  # Windows Script Files
    ".ps1", ".ps1xml", ".psc1", ".psc2",            # PowerShell Scripts
    ".msh", ".msh1", ".msh2", ".mshxml",            # Microsoft Shell Scripts
    ".reg", ".ini",                                 # Registry/Config Files
    ".cpl", ".dll", ".lnk",                         # Control Panel Applets, Libraries, Shortcuts
]

SAFE_MIME_TYPES = [
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp", "image/tiff", "image/svg+xml",
    "text/plain", "text/html",
    "video/mp4", "video/webm", "video/ogg", "video/x-msvideo",
    "audio/mpeg", "audio/wav", "audio/ogg", "audio/flac",
    "application/json", "application/xml", "application/rtf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/pdf",
    "application/zip",
    "application/x-rar-compressed",
]

DANGEROUS_MIME_TYPES = [
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/x-msi",
    "application/x-sh",
    "application/x-shellscript"
]

# Extension → MIME type mapping
EXTENSION_MIME_MAP = {
    # Images
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".png": ["image/png"],
    ".gif": ["image/gif"],
    ".bmp": ["image/bmp"],
    ".webp": ["image/webp"],
    ".tiff": ["image/tiff"],
    ".svg": ["image/svg+xml"],

    # Text / Web
    ".txt": ["text/plain"],
    ".html": ["text/html"],
    ".json": ["application/json"],
    ".xml": ["application/xml"],
    ".rtf": ["application/rtf"],

    # Documents
    ".pdf": ["application/pdf"],
    ".doc": ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".xls": ["application/vnd.ms-excel"],
    ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ".pptx": ["application/vnd.openxmlformats-officedocument.presentationml.presentation"],

    # Archives
    ".zip": ["application/zip"],
    ".rar": ["application/x-rar-compressed"],
    ".7z": ["application/x-7z-compressed"],
    ".tar": ["application/x-tar"],
    ".cab": ["application/vnd.ms-cab-compressed"],
    ".msp": ["application/octet-stream"],

    # Video
    ".mp4": ["video/mp4"],
    ".webm": ["video/webm"],
    ".ogg": ["video/ogg", "audio/ogg"],
    ".avi": ["video/x-msvideo"],

    # Audio
    ".mp3": ["audio/mpeg"],
    ".wav": ["audio/wav"],
    ".flac": ["audio/flac"],

    # Executables / Scripts
    ".exe": ["application/x-msdownload", "application/x-dosexec"],
    ".com": ["application/x-msdos-program"],
    ".scr": ["application/x-msdownload"],
    ".pif": ["application/x-msdos-program"],
    ".application": ["application/x-msdownload"],
    ".msi": ["application/x-msi"],
    ".bat": ["application/x-sh", "application/x-shellscript"],
    ".cmd": ["application/x-sh", "application/x-shellscript"],
    ".vbs": ["text/vbscript"],
    ".vbe": ["text/vbscript"],
    ".js": ["application/javascript", "text/javascript"],
    ".jse": ["application/javascript", "text/javascript"],
    ".ws": ["application/x-ws"],
    ".wsc": ["application/x-ws"],
    ".wsh": ["application/x-ws"],
    ".wsf": ["application/x-ws"],
    ".ps1": ["application/x-sh", "application/x-shellscript", "text/plain", "application/x-powershell", "text/x-powershell"],
    ".ps1xml": ["text/xml"],
    ".psc1": ["text/xml"],
    ".psc2": ["text/xml"],
    ".msh": ["application/x-sh"],
    ".msh1": ["application/x-sh"],
    ".msh2": ["application/x-sh"],
    ".mshxml": ["text/xml"],

    # System / Config
    ".dll": ["application/x-msdownload", "application/x-dosexec"],
    ".lnk": ["application/x-ms-shortcut", "application/x-msdos-program"],
    ".ini": ["text/plain"],
    ".reg": ["text/plain"],
    ".cpl": ["application/x-cpl"],
}


HIGH_ENTROPY_ALLOWED = {
    "application/zip",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "application/x-gzip",
    "application/x-7z-compressed"
}
