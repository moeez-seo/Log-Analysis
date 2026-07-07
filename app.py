# app.py
import sys
import os
from parser import parse_log_file
from analyzer import analyze_logs
from reports import print_summary, export_markdown_report

def print_header():
    print("\n" + "="*50)
    print(" Basic Log Analysis Project ")
    print("="*50)
    print(" Defensive Security / Blue-Team Tool ".center(50))
    print("="*50 + "\n")

def menu_analyze_file(state):
    print("\n[+] Analyze Log File")
    filepath = input("Enter the path to the log file (e.g., sample.log): ").strip()
    
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' does not exist.")
        return
        
    try:
        print(f"[*] Parsing {filepath}...")
        parsed_events = parse_log_file(filepath)
        print("[*] Analyzing events...")
        summary = analyze_logs(parsed_events)
        
        state['current_file'] = filepath
        state['summary'] = summary
        
        print("[+] Analysis complete. Use Option 2 to view the summary.")
    except Exception as e:
        print(f"[-] Error parsing log file: {e}")

def menu_view_summary(state):
    if not state.get('summary'):
        print("\n[-] No log file has been analyzed yet. Please run Option 1 first.")
        return
        
    print_summary(state['summary'], state['current_file'])

def menu_export_report(state):
    if not state.get('summary'):
        print("\n[-] No log file has been analyzed yet. Please run Option 1 first.")
        return
        
    try:
        path = export_markdown_report(state['summary'], state['current_file'])
        print(f"\n[+] Success! Report exported to:\n    {path}")
    except Exception as e:
        print(f"\n[-] Error exporting report: {e}")

def main():
    state = {'current_file': None, 'summary': None}
    
    while True:
        print_header()
        print("1. Analyze log file")
        print("2. View suspicious activity summary")
        print("3. Export report")
        print("4. Exit")
        
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == '1':
            menu_analyze_file(state)
        elif choice == '2':
            menu_view_summary(state)
        elif choice == '3':
            menu_export_report(state)
        elif choice == '4':
            print("\nExiting. Stay secure!")
            sys.exit(0)
        else:
            print("\n[-] Invalid choice. Please select 1-4.")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
