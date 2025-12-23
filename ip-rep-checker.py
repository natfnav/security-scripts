#!/usr/bin/env python3
"""
IP Reputation Checker

This script checks your current IP address on the AbuseIPDB threat database
"""

import requests
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def get_current_ip():
    """Get the current public IP address"""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        response.raise_for_status()
        return response.json()['ip']
    except requests.RequestException as e:
        print(f"{Colors.RED}Error getting IP address: {e}{Colors.END}")
        return None

def check_ip_reputation(ip_address, api_key):
    """Check IP reputation using AbuseIPDB API"""
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"{Colors.RED}Error checking IP reputation: {e}{Colors.END}")
        return None

def display_results(ip_address, data):
    """Display the reputation check results in a formatted way"""
    # This function is no longer used but kept for reference
    pass

def save_results_to_file(ip_address, data, output_folder, filename):
    """Save results to a text file in the specified folder"""
    try:
        # Create the folder if it doesn't exist
        Path(output_folder).mkdir(parents=True, exist_ok=True)
        
        # Create full filepath
        filepath = os.path.join(output_folder, filename)
        
        # Open file and write results
        with open(filepath, 'w') as f:
            if not data or 'data' not in data:
                f.write("No data received from API\n")
                return False
            
            info = data['data']
            
            f.write("="*60 + "\n")
            f.write("IP REPUTATION REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"IP Address: {ip_address}\n")
            f.write(f"Check Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Abuse confidence score
            score = info.get('abuseConfidenceScore', 0)
            if score == 0:
                status = "CLEAN"
            elif score < 25:
                status = "LOW RISK"
            elif score < 75:
                status = "MODERATE RISK"
            else:
                status = "HIGH RISK"
            
            f.write(f"Reputation Status: {status}\n")
            f.write(f"Abuse Confidence Score: {score}%\n\n")
            
            # Additional information
            f.write(f"Country: {info.get('countryName', 'Unknown')} ({info.get('countryCode', 'N/A')})\n")
            f.write(f"ISP: {info.get('isp', 'Unknown')}\n")
            f.write(f"Domain: {info.get('domain', 'N/A')}\n")
            f.write(f"Usage Type: {info.get('usageType', 'Unknown')}\n")
            f.write(f"Total Reports: {info.get('totalReports', 0)}\n")
            f.write(f"Distinct Users Reported: {info.get('numDistinctUsers', 0)}\n")
            f.write(f"Last Reported: {info.get('lastReportedAt', 'Never')}\n")
            f.write(f"Whitelisted: {'Yes' if info.get('isWhitelisted') else 'No'}\n")
            
            # Report categories if available
            if info.get('reports'):
                f.write(f"\nRecent Reports:\n")
                for report in info['reports'][:5]:  # Show last 5 reports
                    categories = ', '.join(map(str, report.get('categories', [])))
                    f.write(f"  - {report.get('reportedAt', 'N/A')}: {categories}\n")
            
            f.write("\n" + "="*60 + "\n")
        
        print(f"{Colors.GREEN}Results saved to {filepath}{Colors.END}")
        return True
    except Exception as e:
        print(f"{Colors.RED}Error saving file: {e}{Colors.END}")
        return False

def main():
    """Main function"""
    print(f"{Colors.BOLD}IP Reputation Checker{Colors.END}")
    print("Powered by AbuseIPDB\n")
    
    # Load environment variables from .env file
    load_dotenv()
    
    # Configure output folder and filename here
    OUTPUT_FOLDER = "./reports"  # Change this to your desired folder path
    OUTPUT_FILENAME = "ip-rep-report.txt"  # Change this to your desired filename
    
    # Get API key from .env file
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        print(f"{Colors.RED}Error: ABUSEIPDB_API_KEY not found in .env file{Colors.END}")
        print(f"{Colors.YELLOW}Please create a .env file in the same directory with:{Colors.END}")
        print(f"  ABUSEIPDB_API_KEY=your_api_key_here")
        sys.exit(1)
    
    # Get current IP
    print("Getting your current IP address...")
    ip_address = get_current_ip()
    
    if not ip_address:
        sys.exit(1)
    
    print(f"Your IP: {ip_address}\n")
    
    # Check reputation
    print("Checking IP reputation against threat database...")
    reputation_data = check_ip_reputation(ip_address, api_key)
    
    if reputation_data:
        save_results_to_file(ip_address, reputation_data, OUTPUT_FOLDER, OUTPUT_FILENAME)
    else:
        print(f"{Colors.RED}Failed to retrieve reputation data{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user{Colors.END}")
        sys.exit(0)