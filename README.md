# Malware Analysis Web App

A web-based platform for basic malware analysis, including static and dynamic checks, PE file inspection, YARA scanning, and integration with VirusTotal.

## Features

- File, PE, and YARA analysis
- String and IOC extraction
- VirusTotal integration for files, URLs, and IPs
- User authentication (register/login)
- PDF report generation

## Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Mohamedsalem80/Malmare
   cd Flask-APP
   ```

2. **Create and activate a virtual environment (recommended):**
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

4. **Prepare folders:**
   - Ensure the following directories exist: `uploads/`, `reports/`, `app/yara/`, `app/iocs/`, `ML_model/Dataset/`
   - Place your YARA rules in `app/yara/`
   - Place your ML model (`malwareclassifier-V2.pkl`) in `ML_model/`

5. **Initialize the user database:**
   ```sh
   python -c "from app.db import init_db; init_db()"
   ```

## Running the App

```sh
python run.py
```

- The app will be available at [http://localhost:5600](http://localhost:5600)

## Usage

- Register a new user or log in.
- Use the navigation to access different checkers:
  - File Checker
  - PE Checker
  - YARA Checker
  - String/IOC Extraction
  - IP/URL Checker
- Upload files or enter data as required.
- Download PDF reports for your analyses.

## Notes

- Requires Python 3.8+
- VirusTotal API key is hardcoded in the source for demo purposes.
- For production, secure your API keys and use environment variables.
- Some features require external tools (e.g., `strings` from binutils).

## License
This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.