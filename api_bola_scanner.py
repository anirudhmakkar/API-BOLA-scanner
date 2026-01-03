#!/usr/bin/env python3
"""
API-BOLA-Scanner: Automated Broken Object Level Authorization (BOLA) Detection Tool

This script automates the detection of BOLA vulnerabilities in REST APIs by:
1. Fuzzing object IDs with multiple user tokens
2. Detecting when resources are accessible across different user contexts
3. Analyzing response patterns for authorization bypasses
4. Generating detailed reports of vulnerable endpoints

Author: Anirudh Makkar
License: MIT
GitHub: https://github.com/yourusername/API-BOLA-Scanner
"""

import requests
import json
import sys
import argparse
from typing import Dict, List, Tuple
import time
from urllib.parse import urljoin
from collections import defaultdict


class BOLAScanner:
    """Automated BOLA vulnerability scanner for REST APIs"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        """
        Initialize the BOLA Scanner
        
        Args:
            base_url: The base URL of the API to test
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.vulnerable_endpoints = []
        self.results = defaultdict(list)
        
    def test_endpoint(self, endpoint: str, token: str, obj_id: str, method: str = "GET") -> Tuple[int, Dict]:
        """
        Test a single endpoint with a specific token and object ID
        
        Args:
            endpoint: The API endpoint path (e.g., /users/123)
            token: Authentication token for the request
            obj_id: Object ID to test
            method: HTTP method (GET, POST, PUT, DELETE)
            
        Returns:
            Tuple of (status_code, response_json)
        """
        try:
            url = urljoin(self.base_url, endpoint.replace("{id}", str(obj_id)))
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            if method == "GET":
                response = self.session.get(url, headers=headers, timeout=self.timeout)
            elif method == "POST":
                response = self.session.post(url, headers=headers, timeout=self.timeout)
            elif method == "PUT":
                response = self.session.put(url, headers=headers, timeout=self.timeout)
            elif method == "DELETE":
                response = self.session.delete(url, headers=headers, timeout=self.timeout)
            else:
                return 405, {}
            
            try:
                return response.status_code, response.json()
            except:
                return response.status_code, {"content": response.text[:100]}
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error: {e}")
            return 0, {}
    
    def fuzz_object_ids(self, endpoint: str, tokens: Dict[str, str], id_range: range, 
                       method: str = "GET") -> None:
        """
        Fuzz endpoint with multiple object IDs across different user contexts
        
        Args:
            endpoint: Endpoint pattern (e.g., /users/{id}/profile)
            tokens: Dict of user_id: token pairs
            id_range: Range of IDs to test
            method: HTTP method to use
        """
        print(f"\n[*] Testing endpoint: {endpoint}")
        print(f"[*] Users to test: {len(tokens)}")
        print(f"[*] ID range: {min(id_range)} - {max(id_range)}")
        
        for test_id in id_range:
            for user_id, token in tokens.items():
                status, response = self.test_endpoint(endpoint, token, test_id, method)
                
                # 200/201 from different user context = potential BOLA
                if status in [200, 201]:
                    # Store detailed result
                    result = {
                        "endpoint": endpoint,
                        "object_id": test_id,
                        "user_token": user_id,
                        "status_code": status,
                        "response_preview": json.dumps(response)[:200]
                    }
                    self.results[endpoint].append(result)
                    
                    # Flag if multiple users can access same resource
                    if self._is_same_resource_accessed_by_different_users(endpoint, test_id):
                        self.vulnerable_endpoints.append(result)
                        print(f"[!] BOLA FOUND: {user_id} accessed object {test_id} at {endpoint}")
        
        time.sleep(1)  # Rate limiting
    
    def _is_same_resource_accessed_by_different_users(self, endpoint: str, obj_id: str) -> bool:
        """Check if same object was accessed by multiple users (indicator of BOLA)"""
        users_accessing_resource = set()
        for result in self.results[endpoint]:
            if result["object_id"] == obj_id and result["status_code"] in [200, 201]:
                users_accessing_resource.add(result["user_token"])
        
        # BOLA = 2+ users accessing same resource without proper authorization
        return len(users_accessing_resource) > 1
    
    def generate_report(self, output_file: str = None) -> Dict:
        """
        Generate a report of findings
        
        Args:
            output_file: Optional file to write report to
            
        Returns:
            Dictionary containing report data
        """
        report = {
            "total_endpoints_tested": len(self.results),
            "vulnerable_endpoints_found": len(self.vulnerable_endpoints),
            "severity": "CRITICAL" if self.vulnerable_endpoints else "SAFE",
            "findings": self.vulnerable_endpoints
        }
        
        print("\n" + "="*60)
        print("BOLA VULNERABILITY SCAN REPORT")
        print("="*60)
        print(f"Endpoints Tested: {report['total_endpoints_tested']}")
        print(f"Vulnerable Endpoints Found: {report['vulnerable_endpoints_found']}")
        print(f"Severity: {report['severity']}")
        print("="*60)
        
        if self.vulnerable_endpoints:
            print("\n[!] VULNERABLE ENDPOINTS:")
            for finding in self.vulnerable_endpoints:
                print(f"\n  Endpoint: {finding['endpoint']}")
                print(f"  Object ID: {finding['object_id']}")
                print(f"  Accessible By: {finding['user_token']}")
                print(f"  Status Code: {finding['status_code']}")
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report


def example_usage():
    """Example usage of the BOLA Scanner"""
    
    # Initialize scanner
    scanner = BOLAScanner(base_url="https://api.example.com")
    
    # Define test tokens for different users
    tokens = {
        "user_1": "token_user_1_xyz123",
        "user_2": "token_user_2_abc456",
        "user_3": "token_user_3_def789"
    }
    
    # Test endpoints with object ID fuzzing
    endpoints_to_test = [
        "/users/{id}/profile",
        "/users/{id}/preferences",
        "/users/{id}/account",
        "/api/v1/documents/{id}",
        "/api/v1/orders/{id}"
    ]
    
    # Fuzz IDs 1-100 for each endpoint
    id_range = range(1, 101)
    
    for endpoint in endpoints_to_test:
        scanner.fuzz_object_ids(endpoint, tokens, id_range, method="GET")
    
    # Generate report
    report = scanner.generate_report(output_file="bola_scan_report.json")
    
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="API BOLA (Broken Object Level Authorization) Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run against API with predefined tokens
  python api_bola_scanner.py -u https://api.example.com -e /users/{id}/profile -t token1 token2 token3
  
  # Scan multiple endpoints
  python api_bola_scanner.py -u https://api.example.com -e /users/{id} /orders/{id} /documents/{id} -t token1 token2
  
  # Specify object ID range
  python api_bola_scanner.py -u https://api.example.com -e /users/{id} -t token1 token2 --id-range 1-1000
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API")
    parser.add_argument("-e", "--endpoints", nargs="+", required=True, 
                       help="Endpoints to test (use {id} as placeholder)")
    parser.add_argument("-t", "--tokens", nargs="+", required=True, 
                       help="Auth tokens for different users")
    parser.add_argument("-m", "--method", default="GET", 
                       help="HTTP method (GET, POST, PUT, DELETE)")
    parser.add_argument("--id-range", default="1-100", 
                       help="Object ID range to fuzz (e.g., 1-100)")
    parser.add_argument("-o", "--output", default="bola_scan_report.json", 
                       help="Output report file")
    
    args = parser.parse_args()
    
    # Parse ID range
    id_min, id_max = map(int, args.id_range.split("-"))
    id_range = range(id_min, id_max + 1)
    
    # Create tokens dict
    tokens = {f"user_{i}": token for i, token in enumerate(args.tokens, 1)}
    
    # Initialize and run scanner
    scanner = BOLAScanner(base_url=args.url)
    
    for endpoint in args.endpoints:
        scanner.fuzz_object_ids(endpoint, tokens, id_range, method=args.method)
    
    # Generate report
    scanner.generate_report(output_file=args.output)
