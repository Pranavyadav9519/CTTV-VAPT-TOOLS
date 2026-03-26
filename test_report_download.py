#!/usr/bin/env python3
"""Test report download functionality"""

import requests
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_report_download():
    """Test downloading reports in different formats"""
    
    # First, get list of scans
    print("Fetching scans list...")
    try:
        response = requests.get(f"{BASE_URL}/api/scans")
        if response.status_code != 200:
            print(f"Failed to get scans: {response.status_code}")
            return False
        
        scans_data = response.json()
        scans = scans_data.get('data', {}).get('scans', [])
        
        if not scans:
            print("No scans found in database")
            return False
        
        print(f"Found {len(scans)} scans")
        
        # Use the first completed scan
        for scan in scans:
            if scan['status'] == 'completed':
                scan_id = scan['id']
                print(f"\nUsing scan ID: {scan_id}")
                
                # Test each format
                formats = ['txt', 'json', 'html', 'pdf']
                
                for fmt in formats:
                    print(f"\nTesting {fmt.upper()} format...")
                    try:
                        url = f"{BASE_URL}/api/report/{scan_id}/download?format={fmt}"
                        response = requests.get(url)
                        
                        if response.status_code == 200:
                            content_length = len(response.content)
                            print(f"  ✓ Success! Downloaded {content_length} bytes")
                            
                            # Save sample
                            ext = fmt if fmt != 'pdf' else 'pdf'
                            filename = f"test_report_sample.{ext}"
                            with open(filename, 'wb') as f:
                                f.write(response.content)
                            print(f"  Saved to: {filename}")
                        else:
                            print(f"  ✗ Failed: {response.status_code}")
                            print(f"    Response: {response.text[:200]}")
                    
                    except Exception as e:
                        print(f"  ✗ Error: {e}")
                
                return True
        
        print("\nNo completed scans found")
        return False
        
    except requests.exceptions.ConnectionError:
        print(f"Cannot connect to {BASE_URL}")
        print("Make sure the server is running: python backend/run.py")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    success = test_report_download()
    sys.exit(0 if success else 1)
