# I dicide to change detection algorithm
# previous algorithm can't detect base64
# this approach we will get only path of http request and send to check whether obfuscated or not

import socket
import threading
import sys
import select
import re
import base64
import binascii
import urllib.parse
import mysql.connector
from urllib.parse import urlparse, unquote, unquote_plus, parse_qs



PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8080


# --- Configuration: Malicious Keywords ---
# This list contains patterns that, if found after decoding/normalization,
# indicate potential obfuscation or malicious intent.
MALICIOUS_KEYWORDS = [
    # Common attack/exploitation patterns
    "script.sh", "systeminfo", "passwd", "etc/passwd", "/admin_panel",
    "backup.tar.gz", ".git/", "phpmyadmin", "shell", "exec", "eval(",
    "cmd=", "action=delete", "upload.php", "wp-login.php", "powershell",
    "whoami", "nc -e", "rm -rf", "wget", "curl", "base64", "nc",
    "select * from", "union select", "xp_cmdshell", "drop table",
    "insert into", "alert(", "document.cookie", "<script>", "onerror="
]


# --- Helper Function: Decoding and Normalization ---
def decode_and_normalize(s):
    """
    Attempts to decode commonly used encodings (URL, Base64, Hex) and
    normalizes path-like strings by resolving redundant path components
    and converting to lowercase.

    Args:
        s (str): The string to decode and normalize.

    Returns:
        list: A list of unique strings representing all successfully decoded and
              normalized forms of the input string, including the original.
              Returns an empty list if input is invalid or empty.
    """
    decoded_forms = []
    
    # Ensure working with string and handle None/empty inputs
    if not isinstance(s, str) or not s:
        return []

    # 1. Initial form (raw string)
    decoded_forms.append(s)

    # Prepare for potential decoding of segment after leading slash (common in URL paths)
    s_no_leading_slash = s[1:] if s.startswith('/') else s

    # 2. URL Decode: Try to URL-decode the string. This is often the first step
    #    as other encodings (Base64, Hex) might be URL-encoded themselves within a URL.
    try:
        url_decoded_s = urllib.parse.unquote_plus(s)
        if url_decoded_s != s:
            decoded_forms.append(url_decoded_s)
        
        # If the original string had a leading slash, also try decoding the part without it
        # and re-add the slash if successful.
        if s.startswith('/') and url_decoded_s != s_no_leading_slash:
            url_decoded_s_no_slash = urllib.parse.unquote_plus(s_no_leading_slash)
            if url_decoded_s_no_slash != s_no_leading_slash: # Check if actual decoding occurred
                decoded_forms.append('/' + url_decoded_s_no_slash)

    except Exception:
        pass # Ignore decoding errors, keep original forms

    # 3. Base64 Decode: Attempt to Base64-decode the string.
    #    We iterate through all current `decoded_forms` as well as the original
    #    `s_no_leading_slash` to catch multi-layered or segment-specific encodings.
    candidates_for_b64 = list(set(decoded_forms + [s_no_leading_slash]))
    for candidate_s in candidates_for_b64:
        if not candidate_s: continue # Skip empty candidates
        try:
            # Heuristic: Base64 strings are multiples of 4 length, and use specific characters.
            # This helps avoid trying to decode non-Base64 strings.
            if len(candidate_s) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in candidate_s):
                base64_decoded_bytes = base64.b64decode(candidate_s)
                base64_decoded_s = base64_decoded_bytes.decode('utf-8', errors='ignore')
                if base64_decoded_s != candidate_s: # Only add if actual decoding happened
                    # If decoding a segment that originally had a leading slash, re-add it.
                    if candidate_s == s_no_leading_slash and s.startswith('/'):
                        decoded_forms.append('/' + base64_decoded_s)
                    else:
                        decoded_forms.append(base64_decoded_s)
        except (base64.binascii.Error, UnicodeDecodeError):
            pass # Not a valid Base64 string, or encoding error

    # 4. Hex Decode: Attempt to Hex-decode the string. Similar logic to Base64.
    candidates_for_hex = list(set(decoded_forms + [s_no_leading_slash]))
    for candidate_s in candidates_for_hex:
        if not candidate_s: continue
        try:
            # Heuristic: Hex strings are even length, and use hex characters.
            if len(candidate_s) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in candidate_s):
                hex_decoded_bytes = binascii.unhexlify(candidate_s)
                hex_decoded_s = hex_decoded_bytes.decode('utf-8', errors='ignore')
                if hex_decoded_s != candidate_s: # Only add if actual decoding happened
                    if candidate_s == s_no_leading_slash and s.startswith('/'):
                        decoded_forms.append('/' + hex_decoded_s)
                    else:
                        decoded_forms.append(hex_decoded_s)
        except (binascii.Error, UnicodeDecodeError):
            pass # Not a valid Hex string, or encoding error

    # 5. Path Normalization and Lowercasing:
    #    After all decoding attempts, normalize paths (e.g., remove /./, resolve /../)
    #    and convert everything to lowercase for case-insensitive pattern matching.
    normalized_forms = set() # Use a set to store unique normalized forms
    for form in decoded_forms: # Iterate through all collected decoded forms
        lower_form = form.lower() # Convert to lowercase immediately
        normalized_forms.add(lower_form) # Add the lowercased form

        # Handle path redundancies (e.g., /./, /../) for path-like strings
        if '/' in lower_form:
            parts = []
            for part in lower_form.split('/'):
                if part == '' or part == '.':
                    continue # Skip empty parts and current directory
                if part == '..':
                    if parts: # If not at root, pop the last part
                        parts.pop()
                else:
                    parts.append(part) # Add other parts
            canonical_path = '/' + '/'.join(parts)
            if canonical_path != lower_form: # Add if the canonical path is different
                normalized_forms.add(canonical_path)
    
    # Return a list of all unique forms found (original, decoded, and normalized)
    return list(set(decoded_forms + list(normalized_forms)))




# --- Main Obfuscation Detection Algorithm ---
def is_obfuscated_http_request(method, full_path, headers, body_bytes):
    """
    Determines if an HTTP request contains obfuscated or potentially malicious content.
    It checks various parts of the request (URL path, query, headers, body)
    by attempting to decode common encodings and then searching for suspicious patterns.

    Args:
        method (str): The HTTP method (e.g., 'GET', 'POST').
        full_path (str): The full request path, including the query string (e.g., '/path?query=value').
                         This should be the raw path string received from the client.
        headers (dict): A dictionary of request headers (keys should be lowercase).
        body_bytes (bytes): The raw request body as bytes.

    Returns:
        tuple: A tuple (bool, str).
               - bool: True if obfuscation/malicious pattern is detected, False otherwise.
               - str: A reason string explaining the detection.
    """
    all_checked_forms = set() # Stores all strings to be checked for malicious patterns

    # 1. Process URL Path and its segments
    parsed_url = urlparse(full_path)
    
    # Add the full raw path and all its decoded/normalized forms
    all_checked_forms.update(decode_and_normalize(parsed_url.path)) 
    
    # Also process individual path segments (e.g., /encoded_segment1/encoded_segment2)
    for segment in parsed_url.path.split('/'):
        if segment: # Avoid empty strings from split (e.g., from `//` or trailing slash)
            all_checked_forms.update(decode_and_normalize(segment))

    # 2. Process Query Parameters (keys and values)
    if parsed_url.query:
        # Try decoding the entire query string first
        all_checked_forms.update(decode_and_normalize(parsed_url.query))
        
        # Then parse key-value pairs and decode each key and value individually
        parsed_query = parse_qs(parsed_url.query)
        for key, values in parsed_query.items():
            all_checked_forms.update(decode_and_normalize(key)) # Add decoded key forms
            for val in values:
                all_checked_forms.update(decode_and_normalize(val)) # Add decoded value forms
                
                # Also add combined key=value forms (useful if a pattern includes '=')
                for decoded_key in decode_and_normalize(key):
                    for decoded_val in decode_and_normalize(val):
                        all_checked_forms.add(f"{decoded_key}={decoded_val}".lower())

    # 3. Process HTTP Headers
    for header_name, header_value in headers.items():
        # Directly check the header value
        all_checked_forms.update(decode_and_normalize(header_value))
        
        # Special handling for Authorization: Basic, which is legitimate Base64
        # We still decode it to check the credentials, but might not flag as "obfuscated"
        # unless the decoded credentials themselves are suspicious.
        if header_name == 'authorization' and header_value.lower().startswith('basic '):
            b64_part = header_value[len('basic '):]
            decoded_auth = decode_and_normalize(b64_part)
            all_checked_forms.update(decoded_auth)
            # You might add a specific check here like:
            # if 'admin:password' in decoded_auth: return True, "Hardcoded creds"

    # 4. Process HTTP Body (primarily for POST/PUT requests with text-based bodies)
    if body_bytes:
        try:
            # Attempt to decode body as UTF-8 string
            body_str = body_bytes.decode('utf-8', errors='ignore')
            all_checked_forms.update(decode_and_normalize(body_str))

            # If Content-Type indicates form-urlencoded, parse it like a query string
            content_type = headers.get('content-type', '').lower()
            if content_type.startswith('application/x-www-form-urlencoded'):
                parsed_body_query = parse_qs(body_str)
                for key, values in parsed_body_query.items():
                    all_checked_forms.update(decode_and_normalize(key))
                    for val in values:
                        all_checked_forms.update(decode_and_normalize(val))
                        for decoded_key in decode_and_normalize(key):
                            for decoded_val in decode_and_normalize(val):
                                all_checked_forms.add(f"{decoded_key}={decoded_val}".lower())

        except Exception:
            pass # Could not decode body as text (e.g., binary file upload), skip text analysis

    # 5. Final Pattern Matching: Check all collected decoded/normalized strings
    for pattern in MALICIOUS_KEYWORDS:
        lower_pattern = pattern.lower() # Ensure case-insensitive matching
        for form_str in all_checked_forms:
            if lower_pattern in form_str.lower():
                return True, f"Detected malicious pattern '{pattern}' in decoded/normalized form: '{form_str}'"

    # 6. Heuristics for General Suspiciousness (beyond specific patterns)
    # These checks look for signs of encoding regardless of the content.
    
    # Combine original path and query string for length comparison
    original_full_url_raw = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
    
    # Heuristic: If a very long original string significantly shrinks after decoding,
    # it indicates data compression or heavy obfuscation.
    decoded_path_forms = decode_and_normalize(parsed_url.path)
    if any(form != parsed_url.path and len(form) < len(parsed_url.path) * 0.7 for form in decoded_path_forms):
         return True, "Suspiciously long original path with significant decoding reduction (potential obfuscation)"

    decoded_query_forms = decode_and_normalize(parsed_url.query)
    if any(form != parsed_url.query and len(form) < len(parsed_url.query) * 0.7 for form in decoded_query_forms):
         return True, "Suspiciously long original query with significant decoding reduction (potential obfuscation)"

    # Heuristic: Excessive URL encoding (e.g., every character is percent-encoded)
    if original_full_url_raw.count('%') > len(original_full_url_raw) / 5: # More than 20% URL encoding
        return True, "Excessive URL encoding detected in path/query"
    
    # Heuristic: JavaScript URI scheme (e.g., `javascript:alert(1)`)
    # Often used for client-side attacks or redirects.
    if parsed_url.scheme == 'javascript':
        return True, "Detected JavaScript URI scheme (client-side obfuscation)"

    # If no specific patterns or suspicious heuristics were triggered
    return False, "No obfuscation or malicious pattern detected"








def handle_client(client_socket):
    #print(f"in handle_client() function")

    thread_id = threading.get_ident()
    thread_name = threading.current_thread().name

    #print(f"We are in thread-name:{thread_name}, and thread-id:{thread_id}---------------")

    target_socket = None
    response_chunk_buffer = None
    transaction_status = None

    try:
        # Read the client's full request
        request_buffer = b""
       
        while True:
        
            chunk = client_socket.recv(4096)
        
            request_buffer += chunk

            if b"\r\n\r\n" in request_buffer:
                
                #print(f"Complete http request caputer = {request_buffer}") #for debug purpose
                break

            if len(request_buffer) > 65536:
                print("Request too large or malformed, stopping read.")
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            
        
        print(f"--We will request for website and return to client on behalf of us")
        
        request_lines = request_buffer.decode('utf-8', errors='ignore').split('\r\n')
        

        target_host = None
        target_port = 80

        #Extract target host from Header
        for line in request_lines:
            if line.lower().startswith("host:"):
                host_header = line[len("host:"):].strip()
                if ':' in host_header:
                    host_parts = host_header.split(':')
                    target_host = host_parts[0]
                    try:
                        target_port = int(host_parts[1])
                    except ValueError:
                        pass
                else:
                    target_host = host_header
                break
        
        #print(f"{target_host}:{target_port}")
        #print(f"0:{request_lines[0]}")
        #print(f"1:{request_lines[1]}")  # Host:
        #print(f"2:{request_lines[2]}")  # User--agent:
        #print(f"3:{request_lines[3]}")  # Accept:



        for line in request_lines:
            if line.lower().startswith('user-agent:'):
                user_agent = line[len('User-Agent:'):].strip()
            

        
        parts = request_lines[0].split(' ')
        method = parts[0]       # Method
        parameter = parts[1]    # Parameter

        client_method = parts[0]
        client_full_path = parts[1]
        client_headers = { 'host': target_host, 'user-agent': user_agent, 'accept': '*/*'}
        client_body_bytes = b''
    
 
        is_obfuscated, reason = is_obfuscated_http_request(client_method, client_full_path, client_headers, client_body_bytes)
        
        print(f"is_obfuscated={is_obfuscated}:reason={reason}")

        if is_obfuscated:
            transaction_status = "BLOCKED"
            print(f"\033[31m[BLOCKED] - obfuscated Request Detected from {client_socket.getpeername()}: {reason}\033[0m]")
            #Send a 403 Forbidden response to the client

            #byte_client_full_path = client_full_path.encode('utf-8')

            block_response_string = (
                f"<html><body>"
                f"<h1>Obfuscated link detected..<h1>"
                f"<h2>System detected that you are trying to access {client_headers} and {client_full_path}</h2>"
                f"</body></html>"
            )

            client_socket.sendall(block_response_string.encode('utf-8'))


            #client_socket.sendall(b"<html><body>"
            #"<h1>""Obfuscated link detected...</h1>"
            #"<h2>System detected that you are tried to access "+ byte_client_full_path + "</h2>"
            #"</body></html>")
            #client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")        
        else:
            transaction_status = "ALLOWED"
            print(f"\033[32m[ALLOWED] - Request from {client_socket.getpeername()} is not look like obfuscated\033[0m]")
            
            # Then, allow proxy calling the destination, and deliver content to the client
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(20)
            target_socket.connect((target_host, target_port))
            target_socket.sendall(request_buffer)
            # This part handle return response to the actual client
            while True:
                response_chunk = target_socket.recv(4096)
                if not response_chunk:
                    break

                response_chunk_buffer = response_chunk
                client_socket.sendall(response_chunk)
        
        

        print(f"555555555555555555555555555555- Can we reach this line 555555555555555")
        #loggin this transaction into database
        conn = mysql.connector.connect(
            host="localhost",
            user="pipe",
            password="password",
            database='capstone'
        )
        cursor = conn.cursor()

        print(f"333333333333333333333333333Report mysql connection = {conn}, and status={transaction_status}")

        sql = f"INSERT INTO http (status, method,host,user_agent,parameter,response) VALUES (%s, %s, %s, %s, %s, %s)" 
        #data = f"'{method}','{target_host}','{user_agent}','{parameter}','{response_chunk}'"
        data = (transaction_status, method, target_host, user_agent, parameter, response_chunk_buffer)

        try:
            cursor.execute(sql, data)
            conn.commit()
            print(f"{transaction_status} - has been inserted into database correctly")
        except Exception as e:
            print(f"Error in mysql connection as: {e}")
        finally:
            cursor.close()
            conn.close()
            


    except socket.timeout:
        print(f"Timeout connecting to {target_host}:{target_port}")
        #client_socket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
        print(f"There is an error in this socket {target_socket} : with request_buffer = {request_buffer}")
    except socket.error as e:
        print(f"socket_error:{e}")
    except Exception as e:
        print(f"Exception in handle_client:{e}")
    finally:
        client_socket.close()
        #print(f"Done Socket close")

    #print(f"We are end thread-name:{thread_name}, and thread-id:{thread_id}---------------")


#------------------------------------ Main function ------------------------------

threadCounter = 0
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server_socket.bind((PROXY_HOST, PROXY_PORT))
    server_socket.listen(5)
    print(f"###################### Program started ##############################")
    #print(f"Python Proxy Server listening on {PROXY_HOST}:{PROXY_PORT}")
    #print("set up iptables rules to redirect HTTP traffic to this port.")
    
    while True:
        #print(f"Wating for incoming packet at port 8080")
        client_socket, addr = server_socket.accept()

        # logging the socket that has been created to the sql
        print(f"------------------Start socket------------")
        # attribute
        print(f"client_socket.type = {client_socket.type}")
        print(f"client_socket.familty = {client_socket.family}")
        print(f"client_socket.proto = {client_socket.proto}")
        
        # method
        print(f"client_socket.getpeername() = {client_socket.getpeername()}")
        print(f"client_socket.getsockname() = {client_socket.getsockname()}")
        print(f"client_socket.gettimeout() = {client_socket.gettimeout()}")
        
        source_ip, port = client_socket.getpeername()

        print(f"ip,port = {source_ip}, {port}")


        #print(f"Accepted connection from {addr}")
        # Handle each client connection in a new thread
        client_handler = threading.Thread(target=handle_client, args=(client_socket,), name=f"Socket_Worker-{threadCounter}")
        client_handler.daemon = True
        client_handler.start()
        #print(f"Thread {threadCounter} has been stated...")
        threadCounter += 1


except OSError as e:
    print(f"Error in OSError: {e}")
except KeyboardInterrupt:
    print("\nProxy server shutting down")
finally:
    server_socket.close()
    print("Server socket closed")


