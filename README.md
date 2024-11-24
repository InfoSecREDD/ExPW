

## **(Ex)ploitDB PoC Writer**

**Description**
The (Ex)ploitDB PoC Writer is a powerful Python-based tool designed for security professionals and enthusiasts. It combines port scanning, exploit searching, and payload generation into a seamless workflow. Leveraging Nmap for network scanning, SearchSploit for exploit discovery, and OpenAI's GPT-4 for rewriting exploit code, this tool streamlines the process of identifying vulnerabilities and creating proof-of-concept (PoC) payloads.

**Features**
- **Port Scanning:** Efficiently scans specified ports on a target IP using TCP or UDP protocols.
- **Exploit Searching:** Integrates with SearchSploit to find relevant exploits based on discovered services.
- **Payload Generation:** Utilizes OpenAI's GPT-4 to rewrite and enhance exploit code for tailored testing.
- **Payload Execution:** Executes generated payloads directly from the tool.
- **Payload Saving:** Option to save generated payloads for future use.
- **User-Friendly Interface:** Enhanced with Rich library for a visually appealing and interactive command-line experience.
- **Environment Configuration:** Easily manage API keys and configurations using a `.env` file.

**Installation**
1. **Clone the Repository**
   ```
   git clone https://github.com/InfoSecREDD/ExPW.git
   ```
2. **Navigate to the Directory**
   ```
   cd ExPW
   ```
3. **Create a Virtual Environment (Optional but Recommended)**
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
4. **Install Dependencies**
   ```
   pip3 install -r requirements.txt
   ```
5. **Configure Environment Variables**
   - Create a `.env` file in the root directory.
   - Add your OpenAI API key:
     ```
     OPENAI_API_KEY=your_openai_api_key_here
     ```

**Usage**
Run the script using the following command structure:
```
python3 expw.py target_ip [--ports PORTS] [--protocol PROTOCOL] [--skipports SKIPPORTS]
```

**Arguments:**
- `target_ip` : Target IP address to scan.

**Options:**
- `--ports` or `-p` : Specify port ranges or single ports to scan. Default is `1-1024`.
  - Examples: `80`, `443`, `1-65535`
- `--protocol` : Choose the protocol to scan (`tcp` or `udp`). Default is `tcp`.
- `--skipports` or `-s` : Specify ports or port ranges to skip during scanning.
  - Examples: `81`, `88-89`

**Examples:**
1. **Basic Port Scan on TCP Ports 1-1024**
   ```
   python3 expw.py 192.168.1.100
   ```
2. **Scan Specific Ports and Use UDP Protocol**
   ```
   python3 expw.py 192.168.1.100 --ports 53 161 --protocol udp
   ```
3. **Scan a Range of Ports and Skip Certain Ports**
   ```
   python3 expw.py 192.168.1.100 --ports 1-1024 --skipports 22 80-85
   ```

**Dependencies**
- Python 3.6+
- Nmap
- SearchSploit
- OpenAI Python Library
- Rich
- python-dotenv

**Contributing**
Contributions are welcome! Please fork the repository and submit a pull request with your enhancements or bug fixes. Ensure that your code adheres to the project's coding standards and includes appropriate documentation.

**License**
This project is licensed under the MIT License. See the `LICENSE` file for details.

**Author**
Developed by InfoSecREDD. For any inquiries or support, please contact via Github Issues.

**Security Notice**
**⚠️ WARNING:** Use this tool responsibly and only on systems you have explicit permission to test. Unauthorized scanning and exploitation can be illegal and unethical.

**Disclaimer**
This tool is provided "as is" without any warranties. The developers are not liable for any misuse or damage caused by this tool.
