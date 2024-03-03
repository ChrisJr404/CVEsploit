import os
import re
import csv
import subprocess
import uuid
from datetime import datetime

def run_msfconsole_with_resource(resource_content):
    resource_file_name = f'temp_resource_{str(uuid.uuid4())}.rc'
    with open(resource_file_name, 'w') as resource_file:
        resource_file.write(resource_content)

    msfconsole = subprocess.Popen(['msfconsole', '-r', resource_file_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = msfconsole.communicate()
    os.remove(resource_file_name)

    if msfconsole.returncode != 0:
        raise Exception(f"Error running msfconsole command: {stderr}")
    return stdout

def search_cve_with_check(cve):
    resource_content = f'search cve:{cve} check:yes\nexit\n'
    return run_msfconsole_with_resource(resource_content)

def search_cve_all(cve):
    resource_content = f'search cve:{cve}\nexit\n'
    return run_msfconsole_with_resource(resource_content)

def search_auxiliary_modules(cve):
    resource_content = f'search cve:{cve} type:auxiliary\nexit\n'
    return run_msfconsole_with_resource(resource_content)

def process_cve_file(file_path):
    with open(file_path, 'r') as file:
        cve_list = file.readlines()

    results_check = []
    results_all = []
    results_auxiliary = []

    for cve in cve_list:
        cve = cve.strip()
        if cve:
            print(f"Searching for: {cve}")
            print("=============")
            result_check = search_cve_with_check(cve)
            result_all = search_cve_all(cve)
            result_auxiliary = search_auxiliary_modules(cve)
            module_lines_check = []
            module_lines_all = []
            module_lines_auxiliary = []
            for line in result_check.splitlines():
                if re.match(r'^\s{2,}\d+\s+([a-zA-Z_]+\/[a-zA-Z_]+\/[a-zA-Z_]+)', line):
                    module_lines_check.append(line)
            for line in result_all.splitlines():
                if re.match(r'^\s{2,}\d+\s+([a-zA-Z_]+\/[a-zA-Z_]+\/[a-zA-Z_]+)', line):
                    module_lines_all.append(line)
            for line in result_auxiliary.splitlines():
                if re.match(r'^\s{2,}\d+\s+([a-zA-Z_]+\/[a-zA-Z_]+\/[a-zA-Z_]+)', line):
                    module_lines_auxiliary.append(line)
            results_check.append((cve, module_lines_check))
            results_all.append((cve, module_lines_all))
            results_auxiliary.append((cve, module_lines_auxiliary))

    # Save the results to CSV files
    os.makedirs("results", exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    csv_file_check = f'results/cve_checks_{today}.csv'
    csv_file_all = f'results/cve_all_{today}.csv'
    csv_file_auxiliary = f'results/auxiliary_{today}.csv'

    write_to_csv(csv_file_check, ['CVE', 'Matching Modules'], results_check)
    write_to_csv(csv_file_all, ['CVE', 'Matching Modules'], results_all)
    write_to_csv(csv_file_auxiliary, ['CVE', 'Auxiliary Modules'], results_auxiliary)

def write_to_csv(file_path, header, data):
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(header)
        for cve, modules in data:
            if modules:
                for module in modules:
                    csv_writer.writerow([cve, module.strip()])
            else:
                csv_writer.writerow([cve, "No Modules Found"])

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python run.py <cve_list_file>")
        sys.exit(1)
    process_cve_file(sys.argv[1])
