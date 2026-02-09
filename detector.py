import os 
import magic
import math
import hashlib
import yara
from config import *
from collections import Counter


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(BASE_DIR, "Rules")


def scan_with_yara(file_path, rules_dir=RULES_DIR):
    matches = []
    try:
        for rules_file in os.listdir(rules_dir):
            if rules_file.endswith(".yar"):
                rules = yara.compile(filepath=os.path.join(rules_dir, rules_file))
                results = rules.match(file_path)
                for match in results:
                    matched_strings = [{"id": s.identifier} for s in getattr(match, "strings", [])]
                    matches.append({
                        "rule": match.rule,
                        "meta": match.meta,
                        "strings": matched_strings
                    })
        return matches
    except Exception as e:
        print(f"[YARA ERROR] {e}")
        return []




def calculate_entropy(file_path) : 
    try : 
        with open(file_path, "rb") as f :
            data = f.read()

        if not data :
                return 0.0

        byte_counts = Counter(data)
        entropy = 0.0
        data_length = len(data)

        for count in byte_counts.values() : 
            probability = count / data_length
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    except Exception as e :
        return None
    


def calculate_hash(file_path, hash_algorithm="sha256") : 
        try : 
            hash_function = hashlib.new(hash_algorithm)
            with open (file_path,"rb") as file :
                for chunk in iter (lambda : file.read(4096),b""):
                    hash_function.update(chunk)
            return hash_function.hexdigest()
        except Exception as e :
            return f"Error calculating hash: {e}"



def get_file_info(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")

    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()
    mime_type = magic.Magic(mime=True).from_file(file_path)

    return file_name, file_extension, mime_type



def check_mismatch (file_extension, mime_type):
    if file_extension in EXTENSION_MIME_MAP:
        expected_mime = EXTENSION_MIME_MAP[file_extension]
        return mime_type not in expected_mime
    return False



def assess_risk(extension, mime_type, entropy=None):
    flags = []
    risk_level = BENIGN
    
    mismatch = check_mismatch(extension, mime_type)
    is_dangerous_mime = mime_type in DANGEROUS_MIME_TYPES
    is_suspicious_extension = extension in SUSPICIOUS_FILE_EXTENSIONS
    is_safe_mime = mime_type in SAFE_MIME_TYPES
    
    if mismatch:
        flags.append("Extension/MIME mismatch")
        risk_level = MALICIOUS
    
    if is_dangerous_mime:
        flags.append("Dangerous MIME type detected")
        risk_level = MALICIOUS
    
    if is_suspicious_extension and risk_level != MALICIOUS:
        flags.append("Suspicious file extension")
        risk_level = SUSPICIOUS

    if entropy is not None:
        if entropy >= 7.5:
            if mime_type not in HIGH_ENTROPY_ALLOWED:
                flags.append(f"Unexpected high entropy: {entropy}")
                risk_level = MALICIOUS
            else:
                flags.append(f"High entropy (expected for this file type): {entropy}")

        elif entropy >= 6.5:
            if mime_type not in HIGH_ENTROPY_ALLOWED:
                flags.append(f"Moderate entropy detected: {entropy}")
                if risk_level == BENIGN:
                    risk_level = SUSPICIOUS
            else:
                flags.append(f"Moderate entropy (expected for this file type): {entropy}")


        if not flags and is_safe_mime:
            flags.append("File appears safe")
            risk_level = BENIGN
        elif not flags:
            flags.append("Unknown or uncommon file type")
            risk_level = SUSPICIOUS
        
        return risk_level, flags



def detect_file(file_path):
    try : 
        file_name, file_extension,mime_type = get_file_info(file_path)
        file_signature = calculate_hash(file_path)
        file_entropy = calculate_entropy(file_path)
        yara_matches = scan_with_yara(file_path)
        risk_level, flags = assess_risk(file_extension, mime_type, file_entropy)

        if yara_matches:
            rule_names = [m["rule"] for m in yara_matches]
            flags.append(f"YARA rule(s) matched: {', '.join(rule_names)}")
            risk_level = MALICIOUS

        return {
            "file_name": file_name,
            "file_path":file_path,
            "file_extension": file_extension,
            "sha256": file_signature,
            "mime_type": mime_type,
            "entropy": file_entropy,
            "yara_matches": yara_matches,
            "risk_level": risk_level,
            "flags": flags
        }
    except Exception as e:
        return {
            "error": str(e),
            "file_path": file_path
        }