from config import BENIGN, SUSPICIOUS, MALICIOUS

def report (result):
    if "error" in result :
        return f"\n Error : {result['error']}\n File Path : {result.get('file_path', 'Unknown')}\n"
    
    report = []
    report.append("\n" + "#" * 50)
    report.append(" File Report ")
    report.append("#" * 50)
    report.append(f"\n File Name : {result['file_name']}")
    report.append(f"\n File Path : {result['file_path']}")
    report.append(f"\n File Extension : {result['file_extension']}")
    report.append(f"\n SHA256 : {result['sha256']}")

    if result.get('entropy') is not None : 
        report.append(f"\n File Entropy : {result['entropy']}")

    if result.get("yara_matches"):
        report.append("\n YARA Matches:")
        for match in result["yara_matches"]:
            report.append(f"\n • Rule: {match['rule']}")

            for s in match["strings"]:
                report.append(f"\n    - Matched {s['id']}")

    report.append(f"\n MIME Type : {result['mime_type']}")
    report.append("\n" + "#" * 50)

    risk_level = result['risk_level']
    if risk_level == BENIGN : 
        report.append("\n Risk Level : Benign")
        report.append(f"\n ✅ {risk_level}")
    elif risk_level == SUSPICIOUS :
        report.append("\n Risk Level : Suspicious")
        report.append(f"\n ⚠️ {risk_level}")
    elif risk_level == MALICIOUS :
        report.append("\n Risk Level : Malicious")
        report.append(f"\n ❌ {risk_level}")
    else:
        report.append("\n Risk Level : Unknown")
        report.append(f"\n ❓ {risk_level}")

    report.append("\n" * 2)
    report.append("#" * 50)
    report.append(" Findings ")
    report.append("#" * 50)

    for flag in result['flags']:
        report.append(f"\n• {flag}")

    report.append("\n" * 2)
    report.append("#" * 50)
    report.append(" End of Report ")
    report.append("#" * 50)

    return "".join(report)


def print_report (result) : 
        print(report(result))