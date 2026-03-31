#!/usr/bin/env python3
"""
Test PR #5 Features:
1. Demo Mode (/api/scan/demo)
2. Internet Scan (/api/scan/internet)
3. Scan History data extraction
4. Virtual network interface filtering
"""
import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_demo_mode():
    """Test Demo Mode endpoint"""
    print("\n✅ TEST 1: Demo Mode Endpoint")
    print("-" * 60)
    try:
        response = requests.post(f"{BASE_URL}/api/scan/demo", json={})
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        if response.status_code == 202:
            print("✅ Demo scan started successfully!")
            return True
        else:
            print("❌ Unexpected status code")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_scan_history():
    """Test Scan History data extraction"""
    print("\n✅ TEST 2: Scan History Data Extraction")
    print("-" * 60)
    try:
        response = requests.get(f"{BASE_URL}/api/scans")
        print(f"Status: {response.status_code}")
        data = response.json()
        
        # Check if data structure is correct (PR #5 fix)
        if "data" in data and isinstance(data["data"], dict) and "scans" in data["data"]:
            scans = data["data"]["scans"]
            print(f"✅ Data extraction working! Found {len(scans)} scans")
            if scans:
                print(f"   Sample scan: {json.dumps(scans[0], indent=2, default=str)[:200]}...")
            return True
        else:
            print("❌ Data structure incorrect")
            print(f"Response: {json.dumps(data, indent=2)[:200]}...")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_internet_scan():
    """Test Internet Scan endpoint"""
    print("\n✅ TEST 3: Internet Scan (Custom CCTV Scanner)")
    print("-" * 60)
    try:
        payload = {
            "target": "192.168.1.0/28",
            "operator_name": "Test User"
        }
        response = requests.post(f"{BASE_URL}/api/scan/internet", json=payload)
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        if response.status_code in [200, 202]:
            print("✅ Internet scan started successfully!")
            return True
        else:
            print("❌ Unexpected status code")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_report_download():
    """Test Report Download endpoints"""
    print("\n✅ TEST 4: Report Download Formats (PDF/Word)")
    print("-" * 60)
    try:
        # First, get a scan to download report for
        scans_response = requests.get(f"{BASE_URL}/api/scans")
        data = scans_response.json()
        
        if not data.get("data", {}).get("scans"):
            print("⚠️  No scans available for report download test")
            return None
        
        scan = data["data"]["scans"][0]
        report_id = scan.get("id")  # Use the database ID, not scan_id
        scan_id = scan.get("scan_id")
        print(f"Using database ID: {report_id}, Scan ID: {scan_id}")
        
        if not report_id:
            print("⚠️  No report ID in scan data")
            return None
        
        # Test PDF download
        pdf_response = requests.get(f"{BASE_URL}/api/report/{report_id}/download?format=pdf")
        print(f"PDF Download Status: {pdf_response.status_code}")
        if pdf_response.status_code == 200:
            print("✅ PDF download works!")
        else:
            print(f"❌ PDF download failed: {pdf_response.text[:100]}")
        
        # Test Word download
        word_response = requests.get(f"{BASE_URL}/api/report/{report_id}/download?format=docx")
        print(f"Word Download Status: {word_response.status_code}")
        if word_response.status_code == 200:
            print("✅ Word (.docx) download works!")
        else:
            print(f"❌ Word download failed: {word_response.text[:100]}")
        
        return pdf_response.status_code == 200 and word_response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🧪 TESTING PR #5 INTEGRATION")
    print("="*60)
    
    results = {}
    
    results["Demo Mode"] = test_demo_mode()
    time.sleep(1)
    
    results["Scan History Fix"] = test_scan_history()
    time.sleep(1)
    
    results["Internet Scan"] = test_internet_scan()
    time.sleep(1)
    
    results["Report Downloads"] = test_report_download()
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else ("⚠️  SKIP" if passed is None else "❌ FAIL")
        print(f"{status} - {test_name}")
    
    total = len([r for r in results.values() if r is not None])
    passed = len([r for r in results.values() if r is True])
    print(f"\n🎯 Overall: {passed}/{total} tests passed")

if __name__ == "__main__":
    main()
