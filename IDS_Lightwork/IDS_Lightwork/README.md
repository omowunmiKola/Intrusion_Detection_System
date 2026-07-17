# Lightweight Full-Stack Intrusion Detection System (IDS)

This project is a custom, full-stack network Intrusion Detection System built from scratch in C, Python (Flask), SQLite, and Vanilla JavaScript/Tailwind CSS. It intercepts raw network packets, detects TCP SYN port scans, logs the attacker IPs securely, and displays the alerts on a real-time web dashboard.

## System Prerequisites

Before running this software, ensure your machine (macOS/Linux) has the following installed:

- **C Compiler:** gcc
- **Packet Capture Library:** libpcap (Standard on macOS/Linux)
- **Python 3:** Version 3.8+
- **Nmap:** Used for simulating the cyber attacks (brew install nmap on macOS or sudo apt install nmap on Linux)

## Step 1: Installation & Environment Setup

This project uses a Python Virtual Environment (venv) to keep its dependencies cleanly isolated from the rest of your system.

- **Open your terminal** and navigate to this project's root folder.
- **Create the virtual environment:**  
   python3 -m venv venv

- **Activate the environment:**  
   source venv/bin/activate

- **Install the required Python modules:**  
   pip install Flask Flask-CORS

## Step 2: Running the IDS Pipeline

Instead of starting the C sniffer, Python server, and web dashboard manually, this project includes an orchestration script (start_ids.sh) that automates the entire boot sequence.

- **Make the script executable** (You only need to do this once):  
   chmod +x start_ids.sh

- **Launch the pipeline:**  
   ./start*ids.sh  
   <br/>\_Note: Because the C sniffer requires direct access to your network interface card (Promiscuous Mode), the terminal will ask for your sudo (administrator) password.*

The script will automatically compile the latest C code, boot the Flask server in the background, open the index.html dashboard in your default browser, and start the C sniffer in the foreground.

## Step 3: Simulating an Attack (Testing)

To verify the IDS is working, you must open a **second, separate terminal window** to act as the attacker.

Run the following Nmap scan against your local machine to trigger the IDS threshold:

**Basic Port Scan:**

sudo nmap -sS -p 1-1000 localhost

**"Hacker" Decoy Scan (Spoofs multiple random IP addresses):**

sudo nmap -sS -p 1-100 -D RND:10 localhost

Watch your first terminal and the web dashboard! You should see the alerts generated, logged to the SQLite database, and rendered on your screen in real-time.

## Step 4: Shutting Down

When you are finished testing the IDS, return to your **first terminal** (where the start_ids.sh script is running) and gracefully shut everything down:

- **Stop the pipeline:** Press Ctrl + C. (The script contains a trap that will safely kill both the C sniffer and the background Python server simultaneously).
- **Deactivate the Python environment:**  
   deactivate  
   <br/>_(Your terminal prompt will return to normal, indicating you have exited the virtual environment)._
