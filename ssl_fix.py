def check_ssl_tls_security(domain):
    """
    Perform detailed checks on SSL/TLS implementation including protocols, 
    cipher suites, and vulnerability detection (POODLE, HEARTBLEED, etc.)
    
    Args:
        domain (str): Domain to check
        
    Returns:
        dict: SSL/TLS security analysis including vulnerabilities and cipher suites
    """
    results = {
        'status': 'ok',
        'score': 0,
        'max_score': 100,
        'details': {},
        'recommendations': [],
        'vulnerabilities': [],
        'protocols': {},
        'cipher_suites': [],
        'enabled_protocols': [],
        'disabled_protocols': []
    }
    
    # First check if domain supports HTTPS
    try:
        # Try to establish a connection with a modern context
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # SSL connection established
                results['details']['supports_tls'] = True
                results['score'] += 25
                
                # Get certificate information
                cert = ssock.getpeercert()
                
                # Extract protocol version
                protocol_version = ssock.version()
                results['details']['protocol_version'] = protocol_version
                
                # Check if using at least TLS 1.2
                if protocol_version == "TLSv1.3":
                    results['details']['protocol_security'] = "excellent"
                    results['score'] += 25
                    results['protocols'][protocol_version] = {"enabled": True, "secure": True}
                    results['enabled_protocols'].append(protocol_version)
                elif protocol_version == "TLSv1.2":
                    results['details']['protocol_security'] = "good"
                    results['score'] += 15
                    results['protocols'][protocol_version] = {"enabled": True, "secure": True}
                    results['enabled_protocols'].append(protocol_version)
                else:
                    results['details']['protocol_security'] = "outdated"
                    results['protocols'][protocol_version] = {"enabled": True, "secure": False}
                    results['enabled_protocols'].append(protocol_version)
                    results['recommendations'].append(f"Upgrade from {protocol_version} to TLS 1.2 or 1.3")
                
                # Get cipher used
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, ssl_version, secret_bits = cipher
                    results['details']['cipher'] = {
                        'name': cipher_name,
                        'version': ssl_version,
                        'bits': secret_bits
                    }
                    
                    # Check cipher strength
                    if secret_bits >= 256:
                        results['details']['cipher_strength'] = "excellent"
                        results['score'] += 25
                    elif secret_bits >= 128:
                        results['details']['cipher_strength'] = "good"
                        results['score'] += 15
                    else:
                        results['details']['cipher_strength'] = "weak"
                        results['recommendations'].append(f"Upgrade cipher strength from {secret_bits} bits to at least 128 bits")
    except (socket.timeout, socket.error, ssl.SSLError) as e:
        results['details']['supports_tls'] = False
        results['details']['error'] = str(e)
        results['recommendations'].append("Implement HTTPS with TLS 1.2 or higher")
        return results
    
    # Now check for vulnerabilities and cipher suites using nmap
    try:
        logging.info(f"Running nmap SSL scan on {domain}")
        # Use nmap with ssl-enum-ciphers and vuln scripts
        command = f"nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443 {domain}"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        stdout, stderr = process.communicate(timeout=60)
        
        if process.returncode != 0 and stderr:
            logging.warning(f"Nmap scan returned non-zero exit code: {stderr}")
        
        # Parse nmap output
        output_lines = stdout.splitlines()
        results['details']['raw_scan'] = stdout
        
        vulnerabilities = []
        cipher_suites = []
        
        # Track if we're in SSL/TLS section
        in_ssl_section = False
        current_protocol = None
        
        for line in output_lines:
            line = line.strip()
            
            # Detect vulnerabilities
            if "VULNERABLE" in line or "CVE" in line:
                vulnerabilities.append(line)
            
            # Detect SSL/TLS section
            if "SSL/TLS:" in line or "TLS:" in line or "SSL:" in line:
                in_ssl_section = True
                
            # Protocol detection
            if in_ssl_section:
                if "SSLv2" in line:
                    results['protocols']["SSLv2"] = {"enabled": "not offered" not in line.lower(), "secure": False}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("SSLv2")
                        vulnerabilities.append("SSLv2 is enabled (severe security risk)")
                        results['score'] -= 30
                    else:
                        results['disabled_protocols'].append("SSLv2")
                elif "SSLv3" in line:
                    results['protocols']["SSLv3"] = {"enabled": "not offered" not in line.lower(), "secure": False}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("SSLv3")
                        vulnerabilities.append("SSLv3 is vulnerable to POODLE attack")
                        results['score'] -= 25
                    else:
                        results['disabled_protocols'].append("SSLv3")
                elif "TLSv1.0" in line:
                    results['protocols']["TLSv1.0"] = {"enabled": "not offered" not in line.lower(), "secure": False}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("TLSv1.0")
                        results['score'] -= 15
                    else:
                        results['disabled_protocols'].append("TLSv1.0")
                elif "TLSv1.1" in line:
                    results['protocols']["TLSv1.1"] = {"enabled": "not offered" not in line.lower(), "secure": False}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("TLSv1.1")
                        results['score'] -= 5
                    else:
                        results['disabled_protocols'].append("TLSv1.1")
                elif "TLSv1.2" in line:
                    results['protocols']["TLSv1.2"] = {"enabled": "not offered" not in line.lower(), "secure": True}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("TLSv1.2")
                    else:
                        results['disabled_protocols'].append("TLSv1.2")
                        results['score'] -= 10
                elif "TLSv1.3" in line:
                    results['protocols']["TLSv1.3"] = {"enabled": "not offered" not in line.lower(), "secure": True}
                    if "offered" in line.lower():
                        results['enabled_protocols'].append("TLSv1.3")
                    else:
                        results['disabled_protocols'].append("TLSv1.3")
                        results['score'] -= 5
                    
                # Cipher suite detection
                if "ciphers:" in line.lower() or "cipher " in line.lower():
                    if line.strip().endswith(":"):
                        current_protocol = line.strip()[:-1].strip()
                elif current_protocol and "|" in line and "Cipher " not in line:
                    cipher_info = line.strip().split("|")
                    if len(cipher_info) >= 3:
                        cipher_name = cipher_info[1].strip()
                        cipher_strength = cipher_info[2].strip() if len(cipher_info) > 2 else "Unknown"
                        if cipher_name and not cipher_name.startswith("Ciphers"):
                            cipher_suites.append({
                                "protocol": current_protocol,
                                "cipher": cipher_name,
                                "strength": cipher_strength
                            })
        
        # Detect weak ciphers
        weak_ciphers = any("weak" in suite.get("strength", "").lower() for suite in cipher_suites)
        if weak_ciphers:
            vulnerabilities.append("Weak cipher suites detected")
            results['score'] -= 15
            results['recommendations'].append("Disable weak cipher suites")
        
        # Add findings to results
        results['vulnerabilities'] = vulnerabilities
        results['cipher_suites'] = cipher_suites
        
        # Additional analysis for POODLE specifically
        poodle_vulnerable = any("POODLE" in vuln for vuln in vulnerabilities)
        if poodle_vulnerable:
            results['details']['poodle_vulnerable'] = True
        else:
            # Check if SSLv3 is enabled which implies POODLE vulnerability
            results['details']['poodle_vulnerable'] = results['protocols'].get('SSLv3', {}).get('enabled', False)
            if results['details'].get('poodle_vulnerable'):
                vulnerabilities.append("Potentially vulnerable to POODLE (SSLv3 enabled)")
                results['vulnerabilities'] = vulnerabilities
                
        # Check for Heartbleed vulnerability
        heartbleed_vulnerable = any("Heartbleed" in vuln or "heartbleed" in vuln.lower() for vuln in vulnerabilities)
        results['details']['heartbleed_vulnerable'] = heartbleed_vulnerable
        
        # Provide recommendations
        if results['details'].get('poodle_vulnerable'):
            results['recommendations'].append("Disable SSLv3 to mitigate POODLE vulnerability")
        
        if results['details'].get('heartbleed_vulnerable'):
            results['recommendations'].append("Update OpenSSL to patch the Heartbleed vulnerability")
            
    except subprocess.TimeoutExpired as e:
        if 'process' in locals():
            process.kill()
        logging.error(f"Nmap scan timed out for {domain}: {str(e)}")
        results['details']['scan_error'] = f"Vulnerability scan timed out: {str(e)}"
    except Exception as e:
        logging.error(f"Error during nmap scan for {domain}: {str(e)}")
        results['details']['scan_error'] = f"Vulnerability scan error: {str(e)}"
    
    # Check HSTS header
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if 'strict-transport-security' in response.headers:
            results['details']['hsts'] = {
                'present': True,
                'value': response.headers['strict-transport-security']
            }
            results['score'] += 10
            
            # Check if includeSubDomains is present
            if 'includesubdomains' in response.headers['strict-transport-security'].lower():
                results['details']['hsts']['includes_subdomains'] = True
                results['score'] += 5
            
            # Check if preload is present
            if 'preload' in response.headers['strict-transport-security'].lower():
                results['details']['hsts']['preload'] = True
                results['score'] += 5
        else:
            results['details']['hsts'] = {
                'present': False
            }
            results['recommendations'].append("Implement HTTP Strict Transport Security (HSTS)")
    except Exception as e:
        results['details']['hsts_test_error'] = str(e)
    
    # Check for weak protocols using OpenSSL
    try:
        # Test for SSLv3 (insecure) - POODLE vulnerability
        sslv3_command = f"echo | openssl s_client -connect {domain}:443 -ssl3 2>&1"
        sslv3_output = subprocess.getoutput(sslv3_command)
        results['details']['sslv3_supported'] = "handshake failure" not in sslv3_output.lower()
        
        # If SSLv3 is supported, add it to vulnerabilities if not already added
        if results['details']['sslv3_supported'] and not results['details'].get('poodle_vulnerable'):
            results['details']['poodle_vulnerable'] = True
            results['vulnerabilities'].append("Potentially vulnerable to POODLE (SSLv3 supported)")
            results['recommendations'].append("Disable SSLv3 to mitigate POODLE vulnerability")
            results['score'] -= 25
            
    except Exception as e:
        logging.error(f"Error checking OpenSSL protocols for {domain}: {str(e)}")
        results['details']['openssl_error'] = str(e)
    
    # Cap the score
    results['score'] = max(0, min(100, results['score']))
    
    return results
