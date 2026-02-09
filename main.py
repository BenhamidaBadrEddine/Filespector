import sys
from detector import detect_file
from reporter import print_report


def main():
    print("\n" + "#"*50)
    print("MAGIC NUMBER FILE SCANNER")
    print("Detects file types and assesses malicious risk")
    print("#"*50 + "\n")
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter the path to the file you want to scan: ").strip()
    
    if not file_path:
        print(" No file path provided. Exiting.")
        return
    
    print(f"\n Scanning file: {file_path}\n")
    result = detect_file(file_path)
    
    print_report(result)


if __name__ == "__main__":
    main()