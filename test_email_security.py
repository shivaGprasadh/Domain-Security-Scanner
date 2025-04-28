import logging
import sys
from utils.security_checker import check_email_security

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   stream=sys.stdout)

def main():
    print("Testing email security functions...")
    
    # Domain to test
    domain = "experience.com"
    print(f"Testing domain: {domain}")
    
    # Run email security check
    results = check_email_security(domain)
    
    # Print the results
    print("\nEmail Security Results:")
    print(f"Score: {results['score']}/{results['max_score']}")
    print(f"Status: {results['status']}")
    
    # Check SPF
    if 'spf' in results['details']:
        print("\nSPF Records:")
        if results['details']['spf']['present']:
            for record in results['details']['spf']['records']:
                print(f"  {record}")
        else:
            print("  No SPF records found")
    
    # Check DKIM
    if 'dkim' in results['details']:
        print("\nDKIM Records:")
        if results['details']['dkim']['present']:
            for selector, records in results['details']['dkim'].get('selectors', {}).items():
                print(f"  Selector: {selector}")
                for record in records:
                    print(f"    {record}")
        else:
            print("  No DKIM records found")
    
    # Check DMARC
    if 'dmarc' in results['details']:
        print("\nDMARC Records:")
        if results['details']['dmarc']['present']:
            for record in results['details']['dmarc']['records']:
                print(f"  {record}")
            if 'policy' in results['details']['dmarc']:
                print(f"  Policy: {results['details']['dmarc']['policy']}")
        else:
            print("  No DMARC records found")
    
    # Check MX
    if 'mx' in results['details']:
        print("\nMX Records:")
        if results['details']['mx']['present']:
            for preference, exchange in results['details']['mx']['records']:
                print(f"  {preference} {exchange}")
            if results['details']['mx'].get('managed_by_provider'):
                print("  Managed by well-known provider: Yes")
        else:
            print("  No MX records found")
    
    # Print recommendations
    if results['recommendations']:
        print("\nRecommendations:")
        for rec in results['recommendations']:
            print(f"  - {rec}")
    
    print("\nTest completed")

if __name__ == "__main__":
    main()