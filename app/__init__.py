from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_restful import Api
from .routes import main_routes
from .auth import auth_routes
from .api import UserAPI


##################
# System Imports #
##################
import shutil
import  hashlib 
from urllib.parse import urlparse
import requests
import sys
from time import sleep 
from os import getenv
import vt ## pip install vt-py ,,, Strings ,, \MinGW\bin\strings.exe  
import json
import subprocess
import re
import math
import pefile
import sys
import os
import yara         # install 'yara-python' module, not the outdated 'yara' module
import logging
import traceback
import codecs
from datetime import datetime
import pickle
import joblib


#########################
# System Implementation #
#########################


# helper
def type(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def HashValues(FilePath):  #This Fuction returns MD5 , SHA1 ,SHA256 , SHA512 as dictionary hashes
    try:
      file = open(FilePath , "r")
      return {
                "MD5" : hashlib.md5(FilePath.encode()).hexdigest(),
                "SHA1" : hashlib.sha1(FilePath.encode()).hexdigest(),
                "SHA256" : hashlib.sha256(FilePath.encode()).hexdigest(),
                "SHA512" : hashlib.sha512(FilePath.encode()).hexdigest()
      }  
    except :
        print("There is an error")    

def extract_indicators(strings):
    patterns = {
    "ip": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "url": re.compile(r'https?://[^\s"<>]+'),
    "Call": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
    "command": re.compile(
        r'\b(powershell|cmd\.exe|regedit|taskkill|netstat|whoami|curl|wget|ftp|sc|schtasks|'
        r'net\s+user|net\s+localgroup|bcdedit|wevtutil|wmic|certutil|rundll32|mshta|'
        r'vssadmin|bitsadmin|python|bash|java|perl)\b',
        re.IGNORECASE
    ),        "filepath": re.compile(r'[A-Za-z]:\\(?:[\w\s\-.]+\\)*[\w\s\-.]+'),
    "Description": re.compile(r'([A-Za-z0-9+/]{20,}={0,2})'),
    "error": re.compile(r'\b(access denied|failed|error|exception|not found)\b', re.IGNORECASE),
    }
    iocs = []

    for string in strings:
        string = string.strip()

        for ioc_type, pattern in patterns.items():
            matches = pattern.findall(string)
            for match in matches:
                iocs.append({
                    'Type' : ioc_type ,
                    'value' : match
                })
                

    return iocs


def GetStringsInfo(FilePath):
    # On Debian, 'strings' should be available via binutils
    strings_path = "strings"  # This uses the one in PATH

    # Optional: check if it's installed
    if not shutil.which(strings_path):
        print(f"[ERROR] 'strings' command not found. Install it via: sudo apt install binutils")
        return []

    result = subprocess.run([strings_path, FilePath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        return result.stdout.splitlines()
    else:
        print(f"[ERROR] Failed to extract strings: {result.stderr}")
        return []

def GetStrings(FilePath):
    strings = GetStringsInfo(FilePath)
    strings = [s.strip().lower() for s in strings if len(s.strip()) >= 4]
    IOCS = extract_indicators(strings)

    # Deduplicate based on 'value' only
    seen_values = {}
    for ioc in IOCS:
        val = ioc['value']
        if val not in seen_values:
            seen_values[val] = ioc['Type']

    output = [{'Type': t, 'value': v} for v, t in seen_values.items()]

    with open("OutPutFile.json", 'w') as file:
        json.dump(output, file, indent=4)

    return {"features": output}



# PEHeader Checker
def PEHeaders(file_path):
    try:
        # Load PE file
        pe = pefile.PE(file_path)

        # -------------------------------------
        # 📌 DOS Header
        print("== DOS Header ==")
        print(f"e_magic: {hex(pe.DOS_HEADER.e_magic)}")
        print(f"e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}\n")

        # -------------------------------------
        # 📌 NT Headers
        print("== NT Headers ==")
        print(f"Signature: {hex(pe.NT_HEADERS.Signature)}")

        # File Header
        print("\n-- File Header --")
        print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"TimeDateStamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
        print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

        # Optional Header
        print("\n-- Optional Header --")
        print(f"AddressOfEntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"Subsystem: {hex(pe.OPTIONAL_HEADER.Subsystem)}")
        print(f"SizeOfImage: {hex(pe.OPTIONAL_HEADER.SizeOfImage)}")
        print(f"SizeOfHeaders: {hex(pe.OPTIONAL_HEADER.SizeOfHeaders)}")

        # Data Directories
        print("\n-- Data Directories --")
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            print(f"{directory.name}: VirtualAddress={hex(directory.VirtualAddress)}, Size={hex(directory.Size)}")

        # -------------------------------------
        # 📦 Section Headers
        print("\n== Section Headers ==")
        for section in pe.sections:
            print(f"Name: {section.Name.decode().rstrip(chr(0))}")
            print(f"  VirtualAddress: {hex(section.VirtualAddress)}")
            print(f"  VirtualSize: {hex(section.Misc_VirtualSize)}")
            print(f"  RawDataSize: {hex(section.SizeOfRawData)}")
            print(f"  RawDataPointer: {hex(section.PointerToRawData)}")
            print(f"  Characteristics: {hex(section.Characteristics)}")
            print('-' * 40)

    except Exception as e:
        print(f"Error analyzing PE file: {e}")


# File Checker
def FileChecker(file_path):
    import requests
    import json
    
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    api = "a2684a632231d2e7881785d24f461e34232cf08c792c9599b774f6fc190e0ae1"
    params = {"apikey": api}
    
    with open(file_path, "rb") as file_to_upload:
        response = requests.post(url, files={"file": file_to_upload}, params=params)
    
    file_url = f"https://www.virustotal.com/api/v3/files/{(response.json())['sha1']}"
    headers = {"accept": "application/json", "x-apikey": api}
    
    response = requests.get(file_url, headers=headers)
    raw_report = response.json()
    
    # Extract the relevant information
    attributes = raw_report["data"]["attributes"]
    # Create a structured report with the desired information
    report = {
        "file_info": {
            "name": attributes.get("meaningful_name", "unable to fetch"),
            "size_kb": attributes["size"] * 10**-3,
            "description": attributes["type_description"],
            "sha256_hash": attributes["sha256"]
        },
        "scan_results": {
            "analysis_results": attributes["last_analysis_results"],
            "malicious_count": sum(1 for result in attributes["last_analysis_results"].values() 
                                  if result["category"] == "malicious"),
            "is_safe": sum(1 for result in attributes["last_analysis_results"].values() 
                          if result["category"] == "malicious") == 0
        }
    }
    
    return report


# URL Checker
# def URLChecker(URL):
#     load_dotenv()  # Loads .env variables if used (optional in your case)

#     apikey = 'a2684a632231d2e7881785d24f461e34232cf08c792c9599b774f6fc190e0ae1'

#     stats_meaning = {
#         'malicious': 'No engine explicitly marked this URL as malicious (i.e., known for phishing, malware, scams, etc.). ✅',
#         'suspicious': 'No engine thought the URL looked suspicious or sketchy based on patterns or heuristics. ✅',
#         'harmless': 'Engines scanned the URL and found it to be safe. ✅',
#         'undetected': 'Engines scanned it but didn’t detect anything, which often means they didn’t have an opinion — “no result.” 🟡',
#         'timeout': 'No engines timed out while analyzing the URL. ✅',
#     }

#     try:
#         with vt.Client(apikey=apikey) as client:
#             analysis = client.scan_url(url=URL, wait_for_completion=True)
#             print(analysis.stats)
#             stats = analysis.stats
#             for k in stats:
#                 print(f"{k}: {stats[k]} — {stats_meaning.get(k, 'No explanation available')}")
#     except Exception as e:
#         print(f"[ERROR] Something went wrong while scanning the URL:\n{e}")

def URLChecker(url):
    import requests
    import json
    import base64
    import time
    
    API_KEY = ''
    
    # Step 1: Submit URL for scanning
    scan_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'x-apikey': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Prepare URL for submission
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    data = f"url={url}"
    
    # Submit the URL for analysis
    scan_response = requests.post(scan_url, headers=headers, data=data)
    
    if scan_response.status_code != 200:
        return {
            "url": url,
            "error": {
                "response_code": scan_response.status_code,
                "message": scan_response.text
            }
        }
    
    # Step 2: Get the analysis results
    # First, try to get existing analysis
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        'x-apikey': API_KEY
    }
    
    # VT might need time to process the URL, wait and retry if needed
    max_attempts = 5
    wait_time = 3  # seconds
    
    for attempt in range(max_attempts):
        analysis_response = requests.get(analysis_url, headers=headers)
        
        if analysis_response.status_code == 200:
            data = analysis_response.json()
            
            # Check if analysis is complete
            if 'last_analysis_results' in data['data']['attributes']:
                results = data['data']['attributes']['last_analysis_results']
                
                # Count various results
                malicious_count = sum(1 for res in results.values() if res.get('category') == 'malicious')
                suspicious_count = sum(1 for res in results.values() if res.get('category') == 'suspicious')
                clean_count = sum(1 for res in results.values() if res.get('category') == 'harmless')
                
                # Create structured report
                report = {
                    "url": url,
                    "scan_results": {
                        "analysis_results": results,
                        "summary": {
                            "malicious_count": malicious_count,
                            "suspicious_count": suspicious_count,
                            "clean_count": clean_count,
                            "total_engines": len(results),
                            "is_safe": malicious_count == 0 and suspicious_count == 0
                        }
                    },
                    "url_info": {
                        "last_analysis_date": data['data']['attributes'].get('last_analysis_date', 'Unknown'),
                        "times_submitted": data['data']['attributes'].get('times_submitted', 'Unknown'),
                        "threat_names": data['data']['attributes'].get('threat_names', []),
                        "reputation": data['data']['attributes'].get('reputation', 'Unknown'),
                        "categories": data['data']['attributes'].get('categories', {})
                    }
                }
                
                # Add optional URL metadata if available
                if 'title' in data['data']['attributes']:
                    report["url_metadata"] = {
                        "title": data['data']['attributes'].get('title', 'Unknown'),
                        "final_url": data['data']['attributes'].get('last_final_url', url),
                        "html_meta": data['data']['attributes'].get('html_meta', {})
                    }
                
                return report
        
        # If we haven't gotten complete results yet, wait and try again
        time.sleep(wait_time)
    
    # If we've tried several times and still don't have results
    return {
        "url": url,
        "status": "pending",
        "message": "Analysis is still in progress. Try again later.",
        "url_id": url_id
    }

# IP Checker
def IPChecker(IP_ADDRESS):
    import requests
    import json
    
    API_KEY = ''
    VT_URL = f'https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}'
    headers = {
        'x-apikey': API_KEY
    }
    
    response = requests.get(VT_URL, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        results = data['data']['attributes']['last_analysis_results']
        
        # Count malicious and clean results
        malicious_count = sum(1 for result in results.values() if result["result"] == "malicious")
        clean_count = sum(1 for result in results.values() if result["result"] == "clean")
        
        # Create a structured report
        report = {
            "ip_address": IP_ADDRESS,
            "scan_results": {
                "analysis_results": results,
                "malicious_count": malicious_count,
                "clean_count": clean_count,
                "is_safe": malicious_count == 0
            },
            "response_code": response.status_code
        }
        
        # Add additional IP information if available
        if 'country' in data['data']['attributes']:
            report["ip_info"] = {
                "country": data['data']['attributes'].get('country', 'Unknown'),
                "asn": data['data']['attributes'].get('asn', 'Unknown'),
                "as_owner": data['data']['attributes'].get('as_owner', 'Unknown'),
                "continent": data['data']['attributes'].get('continent', 'Unknown')
            }
        
        return report
    else:
        # Return error information if the request failed
        return {
            "ip_address": IP_ADDRESS,
            "error": {
                "response_code": response.status_code,
                "message": response.text
            }
        }

import pefile
import pandas as pd
import math

import pefile
import math
import pandas as pd
import joblib

# Function to calculate entropy of a section
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def extract_features(file_path, output_type='DataFrame'):
    pe = None
    try:
        pe = pefile.PE(file_path)

        features = {
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'DirectoryEntryImportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'SectionMaxChar': len(pe.sections),
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'SectionMinEntropy': None,  # Placeholder, to calculate
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'SectionMinVirtualsize': None  # Placeholder, to calculate
        }

        # Calculate SectionMinEntropy
        entropies = []
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            entropies.append(entropy)

        if entropies:
            features['SectionMinEntropy'] = min(entropies)

        # Calculate SectionMinVirtualsize
        features['SectionMinVirtualsize'] = min(section.Misc_VirtualSize for section in pe.sections)

        if output_type == 'DataFrame':
            return pd.DataFrame([features])
        else:
            return features

    finally:
        if pe is not None:
            pe.close()  # <-- Close file handle to release the file


def PEChecker(file_path):
    # Load model once if you want, or consider caching it outside this function
    model = joblib.load('ML_model/malwareclassifier-V2.pkl')

    features_df = extract_features(file_path, output_type='DataFrame')  
    prediction = model.predict(features_df)

    print(f"Prediction: {prediction[0]}")  # 0 for benign, 1 for malicious
    if prediction[0] == 1:
        print("The file is likely malicious.")
    else:
        print("The file is likely benign.")

    features_dict = extract_features(file_path, output_type='json')
    state = "malicious" if prediction[0] == 1 else "benign"
    print(features_dict)
    features_dict['state'] = state
    return features_dict


def YARA(file_to_scan):
    logging.basicConfig(level=logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger('sigbase').addHandler(console)

    YARA_RULE_DIRECTORIES = [r'/home/parrot/Documents/security/Flask-APP/app/yara']
    FILENAME_IOC_DIRECTORY = r'/home/parrot/Documents/security/Flask-APP/app/iocs'

    compiledRules = None
    errors = []
    matches_summary = []

    def walk_error(err):
        try:
            if "Error 3" in str(err):
                errors.append(f"Directory walk error: {removeNonAsciiDrop(str(err))}")
                sys.exit(1)
        except UnicodeError:
            errors.append("Unicode decode error in walk error message")
            sys.exit(1)

    def removeNonAsciiDrop(string):
        try:
            return "".join(i for i in string if 31 < ord(i) < 127)
        except Exception:
            traceback.print_exc()
            return "error"

    def transformOS(regex, platform):
        if platform != "windows":
            regex = regex.replace(r'\\', r'/').replace(r'C:', '')
        return regex

    def replaceEnvVars(path):
        new_path = path
        res = re.search(r"([@]?%[A-Za-z_]+%)", path)
        if res:
            env_var_full = res.group(1)
            env_var = env_var_full.replace("%", "").replace("@", "")
            if env_var in os.environ:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))
        if path[:11].lower() == "\\systemroot":
            new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])
        if path[:8].lower() == "system32":
            new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])
        return new_path

    def initialize_filename_iocs():
        try:
            for ioc_filename in os.listdir(FILENAME_IOC_DIRECTORY):
                if 'filename' in ioc_filename:
                    logging.info(f"Compiling Filename IOCs from {ioc_filename}")
                    with codecs.open(os.path.join(FILENAME_IOC_DIRECTORY, ioc_filename), 'r', encoding='utf-8') as file:
                        lines = file.readlines()
                        last_comment = ""
                        for line in lines:
                            try:
                                if re.search(r'^[\s]*$', line):
                                    continue
                                if re.search(r'^#', line):
                                    last_comment = line.lstrip("#").strip()
                                    continue
                                line = line.rstrip()
                                if ";" in line:
                                    row = line.split(';')
                                    regex = row[0]
                                    score = row[1] if row[1].isdigit() else 60
                                    desc = last_comment if row[1].isdigit() else row[1]
                                    regex_fp = row[2] if len(row) > 2 else None
                                else:
                                    regex = line
                                    desc = last_comment
                                    score = 60
                                    regex_fp = None

                                regex = transformOS(replaceEnvVars(regex), "windows")
                                regex_fp_comp = re.compile(transformOS(replaceEnvVars(regex_fp), "windows")) if regex_fp else None

                                # Here you may want to store these filename IOCs somewhere if used later

                            except Exception:
                                traceback.print_exc()
                                logging.error(f"Error reading line: {line}")
                                sys.exit(1)

        except Exception:
            traceback.print_exc()
            logging.error(f"Error reading File IOC file: {ioc_filename}")
            sys.exit(1)

    def initialize_yara_rules():
        nonlocal compiledRules
        yaraRules = ""
        dummy = ""

        try:
            for yara_rule_directory in YARA_RULE_DIRECTORIES:
                if not os.path.exists(yara_rule_directory):
                    errors.append(f"YARA rules directory does not exist: {yara_rule_directory}")
                    continue
                logging.info(f"Processing YARA rules folder {yara_rule_directory}")
                for root, directories, files in os.walk(yara_rule_directory, onerror=walk_error, followlinks=False):
                    for file in files:
                        try:
                            yaraRuleFile = os.path.join(root, file)
                            if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                                continue
                            extension = os.path.splitext(file)[1].lower()
                            if extension == ".yar":
                                with open(yaraRuleFile, 'r', encoding='utf-8') as rulefile:
                                    data = rulefile.read()
                                    yaraRules += data + "\n"
                        except Exception as e:
                            errors.append(f"Error reading signature file {file}: {e}")
                            traceback.print_exc()
                            continue

            if yaraRules:
                logging.info("Compiling all YARA rules at once...")
                compiledRules = yara.compile(source=yaraRules, externals={
                    'filename': dummy,
                    'filepath': dummy,
                    'extension': dummy,
                    'filetype': dummy,
                    'md5': dummy,
                    'owner': dummy
                })
                logging.info("Successfully compiled YARA rules.")
            else:
                errors.append("No YARA rules found to compile!")
                sys.exit(1)

        except Exception:
            traceback.print_exc()
            errors.append("Error during YARA rule compilation.")
            sys.exit(1)

    def scan_file(file_path):
        if not os.path.exists(file_path):
            errors.append(f"File not found: {file_path}")
            return
        if not os.access(file_path, os.R_OK):
            errors.append(f"File is not readable: {file_path}")
            return
        if not compiledRules:
            errors.append("YARA rules were not compiled.")
            return

        logging.info(f"Scanning file: {file_path}")
        try:
            matches = compiledRules.match(file_path)
            if matches:
                for match in matches:
                    match_info = {
                        'rule': match.rule,
                        'meta': match.meta if hasattr(match, 'meta') else {}
                    }
                    matches_summary.append(match_info)
            else:
                logging.info("No YARA rule matched the file.")
        except Exception as e:
            errors.append(f"Error scanning file: {file_path} - {str(e)}")
            traceback.print_exc()

    # === Main flow ===
    initialize_yara_rules()
    initialize_filename_iocs()
    scan_file(file_to_scan)

    result = {
        "file": file_to_scan,
        "matches": matches_summary,
        "errors": errors
    }
    return result


########################
# Application Creation #
########################

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config['SECRET_KEY'] = 'ccff89b0f16fd293ef8440d741738d7b6a8d0099de1444376aca127b97dc6558'

    CSRFProtect(app)

    app.register_blueprint(main_routes)
    app.register_blueprint(auth_routes)

    api = Api(app, prefix="/api/v1")
    api.add_resource(UserAPI, '/users')

    @app.errorhandler(404)
    def not_found(e):
        return app.jinja_env.get_or_select_template('error/404.html').render(error=e), 404

    return app
