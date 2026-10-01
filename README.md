Passive Recon Tool

A simple Python-based passive reconnaissance tool for gathering basic publicly available information about a domain.

What It Does

The tool provides several reconnaissance functions, including:

- IP address information
- WHOIS information
- DNS information
- Website information
- A full passive scan combining the available checks

The tool is intended for authorized security testing, learning, and reconnaissance of systems you own or have permission to assess.

Requirements

Before using the tool, make sure you have:

- Python 3
- An active internet connection
- Linux/Kali Linux or another compatible environment

Installation

Clone the repository:

git clone https://github.com/Abdoulsuleiman86/passive_recon_tool.git

Enter the project directory:

cd passive_recon_tool

Running the Tool

Start the program with:

python3 main.py

You should then see the available options in the menu.

Choose an option and enter the domain you are authorized to test.

Example

Choose an option:
1. IP Information
2. WHOIS Information
3. DNS Information
4. Web Information
5. Full Passive Scan
6. Exit

For a safe initial test, you can use:

example.com

Important

Only use this tool against domains and systems that you own or have explicit permission to test.

Do not use it to access, attack, or interfere with systems without authorization.

Troubleshooting

The tool cannot retrieve information

Make sure your computer has an active internet connection.

You can test your connection with:

ping -c 3 google.com

If the connection works but individual reconnaissance functions time out, the external service being queried may be unavailable or blocking the request.

Python is not found

Check whether Python 3 is installed:

python3 --version

If Python 3 is installed, run the program with:

python3 main.py

Project Structure

passive_recon_tool/
├── main.py
├── README.md
└── .gitignore

License

No license has been specified for this project yet.

