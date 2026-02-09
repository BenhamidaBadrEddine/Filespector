# Filespector — File Risk Assessment Tool

Filespector is a Python-based static malware analysis tool that evaluates file risk using heuristics and rule-based detection.  
It combines file signature analysis, entropy calculation, MIME type verification, and YARA rules to assess suspicious or potentially malicious behavior.  
The project is learning-focused and serves as a foundation for more advanced malware analysis and endpoint security systems.


## Features

- Detects file type using magic numbers and MIME type
- Calculates file entropy to identify obfuscation or packing
- Detects mismatches between file extension and MIME type
- Uses YARA rules to detect suspicious strings and behaviors
- Generates a clear and structured scan report
- Assigns a risk level: Benign, Suspicious, or Malicious

## How It Works

1. The file is analyzed to extract:
   - File name and extension
   - MIME type
   - SHA256 hash
2. Shannon entropy is calculated to detect abnormal randomness.
3. The file extension is compared with the detected MIME type.
4. YARA rules are applied to scan for suspicious patterns.
5. All results are combined to assess the final risk level.
6. A detailed report is printed showing findings and matched rules.

## Project Structure

```
Filespector/
├── main.py          # Entry point
├── detector.py      # Core detection logic
├── reporter.py      # Report generation
├── config.py        # Configuration and constants
├── Rules/
│   └── suspicious.yar
```

## Requirements

- Python 3.10+
- yara-python
- python-magic

Install dependencies using:

```bash
pip install yara-python python-magic
```

## Usage

Run the scanner using:

```bash
python main.py
```

Or scan a specific file directly:

```bash
python main.py path/to/file
```

The tool will output a detailed report including entropy, YARA matches, and risk level.

### Example Output

##################################################
MAGIC NUMBER FILE SCANNER
Detects file types and assesses malicious risk
##################################################

Enter the path to the file you want to scan: C:\path\to\canva.pdf

 Scanning file: C:\path\to\canva.pdf


################################################## File Report ##################################################

 File Name : canva.pdf
 
 File Path : C:\path\to\canva.pdf
 
 File Extension : .pdf
 
 SHA256 : 1ee935319793923e83e0a652b3b239fca3f7dcaeaf6c6149ca88e4aaa5de7764
 
 File Entropy : 7.29
 
 YARA Matches:
 
 • Rule: Suspicious_strings
    - Matched $net4
 MIME Type : application/pdf
 
 
##################################################
 Risk Level : Malicious
 ❌ Malicious

################################################## Findings ##################################################

• Moderate entropy (expected for this file type): 7.29
• YARA rule(s) matched: Suspecious_strings

################################################## End of Report ##################################################


## Target Audience

- Cybersecurity students
- Malware analysis beginners
- Blue team / SOC trainees
- Anyone learning YARA and static analysis

## Limitations

- This tool does not execute files.
- Detection is rule-based and heuristic-based, not signature-complete.
- False positives are possible, especially with aggressive YARA rules.

## Future Improvements

- Recursive directory scanning
- Quarantine mechanism
- Export reports to JSON or HTML
- More advanced YARA rules
- Integration with VirusTotal

## Disclaimer

This project is for educational and research purposes only.
It should not be used as a replacement for professional antivirus software.
