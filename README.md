SENTINEL — Phishing URL Detection Tool
SENTINEL is a Python-based phishing URL detection tool designed to identify potentially suspicious URLs through rule-based analysis. It provides risk assessments, scan history, and report export functionality through a desktop graphical interface.

Features
URL analysis using suspicious indicators
Risk classification and explanations
Detection of IP-based URLs
Analysis of suspicious keywords and URL patterns
Graphical user interface built with Tkinter
Persistent scan history using SQLite
Searchable scan history
CSV export for scan records
Text-based scan reports
Sample URLs for testing
Technology Stack
Python
Tkinter
SQLite
Regular expressions
URL parsing
CSV
Getting Started
Requirements
Python 3.13 or a compatible Python 3 version
Tkinter support
The project uses Python's standard library and does not require additional package installations.

Run the Application
Clone or download this repository.
Open the project folder in VS Code or a terminal.
Run:
python main.py
If your system uses the Python launcher, you can also try:

py main.py
How It Works
Enter a URL into the application.
Start the scan.
Review the assigned risk level and the indicators detected.
Open scan history to review previous scans.
Export scan records or individual reports when needed.
Testing
Test the application using legitimate URLs and safe, deliberately constructed suspicious URL examples. Avoid visiting suspicious URLs in a browser.

Limitations
SENTINEL uses rule-based analysis. It is an educational security project, not a complete phishing detection service.

A URL classified as low risk is not guaranteed to be safe, and a suspicious URL classification does not prove that a site is malicious. The application should not be treated as a replacement for professional threat intelligence or security tools.

Future Improvements
Web-based interface
Threat intelligence API integration
Machine-learning-based URL classification
Additional detection rules
Automated testing
Disclaimer
This project is intended for educational and defensive cybersecurity purposes. Always exercise caution when handling unfamiliar URLs.

Author
Ansh Chauhan

GitHub: https://github.com/ansh09-dot
