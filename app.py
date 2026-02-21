"""
File Identifier & Malware Checker
A web application that identifies file types and checks for malware using VirusTotal API

Author: [Sanche3t]
"""

import os
import hashlib
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import requests

# ============================================================================
# SETUP: Load environment variables and create Flask app
# ============================================================================

load_dotenv()  
app = Flask(__name__)


VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')


UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Max file size: 32MB


# ============================================================================
# FUNCTION 1: Calculate SHA-256 Hash
# ============================================================================

def calculate_sha256(filepath):
    """
    Calculate the SHA-256 hash of a file.
    
    A hash is like a unique fingerprint for a file.
    Even a tiny change in the file will completely change the hash.
    
    Args:
        filepath: Path to the file
        
    Returns:
        A 64-character hexadecimal string (the hash)
    """
    sha256_hash = hashlib.sha256()  # Create a SHA-256 hash object
    
    # Open the file in binary mode (rb = read binary)
    with open(filepath, 'rb') as f:
        # Read file in chunks of 4096 bytes
        # This is memory-efficient for large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)  # Add this chunk to the hash
    
    # Return the hash as a readable hex string
    return sha256_hash.hexdigest()


# ============================================================================
# FUNCTION 2: Identify File Type
# ============================================================================

def identify_file_type(filepath):
    """
    Identify file type by reading "magic numbers" (file signatures).
    
    Every file type has special bytes at the beginning that identify it.
    For example, all PNG images start with the bytes: 89 50 4E 47
    
    Args:
        filepath: Path to the file
        
    Returns:
        A string describing the file type
    """
    
    # Dictionary of file signatures (magic numbers)
    # The key is the byte pattern, the value is the file type name
    file_signatures = {
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF89a': 'GIF Image',
        b'GIF87a': 'GIF Image (older version)',
        b'%PDF': 'PDF Document',
        b'PK\x03\x04': 'ZIP Archive (or Office document)',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x1f\x8b': 'GZIP Compressed File',
        b'MZ': 'Windows Executable (EXE/DLL)',
        b'\x7fELF': 'Linux Executable',
        b'BM': 'Bitmap Image (BMP)',
        b'ID3': 'MP3 Audio',
        b'\x00\x00\x00\x18ftypmp42': 'MP4 Video',
        b'\x00\x00\x00\x20ftypisom': 'MP4 Video',
    }
    
    # Read the first 20 bytes of the file
    with open(filepath, 'rb') as f:
        file_header = f.read(20)
    
    # Check if the file starts with any known signature
    for signature, file_type in file_signatures.items():
        if file_header.startswith(signature):
            return file_type
    
    # If no match found, just show the file extension
    file_extension = os.path.splitext(filepath)[1]
    return f"Unknown Type ({file_extension} file)"


# ============================================================================
# FUNCTION 3: Check VirusTotal
# ============================================================================

def check_virustotal(file_hash):
    """
    Check if a file hash is known to VirusTotal and if it's malicious.
    
    VirusTotal has a database of billions of files. Instead of uploading
    the entire file, we just send the hash (fingerprint) and ask:
    "Have you seen this file before? Is it safe?"
    
    Args:
        file_hash: The SHA-256 hash of the file
        
    Returns:
        A dictionary with scan results
    """
    
    # Check if API key is set
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'your_api_key_here':
        return {
            'error': 'API key not configured',
            'message': 'Please add your VirusTotal API key to the .env file'
        }
    
    # Build the URL for the API request
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    # Headers include our API key for authentication
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        # Send GET request to VirusTotal
        response = requests.get(url, headers=headers, timeout=10)
        
        # Check the response status code
        if response.status_code == 200:
            # Success! File found in database
            data = response.json()
            
            # Extract scan statistics
            stats = data['data']['attributes']['last_analysis_stats']
            
            # stats contains:
            # - malicious: number of engines that detected malware
            # - suspicious: number of engines that found something suspicious
            # - undetected: number of engines that found nothing
            # - harmless: number of engines that confirmed it's safe
            
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            
            return {
                'found': True,
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'total': total_engines,
                'is_safe': malicious_count == 0 and suspicious_count == 0,
                'scan_date': data['data']['attributes'].get('last_analysis_date', 'Unknown')
            }
            
        elif response.status_code == 404:
            # File not found in VirusTotal database
            return {
                'found': False,
                'message': 'File not found in VirusTotal database (might be new/rare)'
            }
            
        elif response.status_code == 429:
            # Too many requests (rate limit exceeded)
            return {
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Free API allows 4 requests per minute.'
            }
            
        else:
            # Other error
            return {
                'error': f'API Error {response.status_code}',
                'message': 'Could not connect to VirusTotal'
            }
            
    except requests.exceptions.Timeout:
        return {
            'error': 'Timeout',
            'message': 'VirusTotal API took too long to respond'
        }
    except Exception as e:
        return {
            'error': 'Connection error',
            'message': str(e)
        }


# ============================================================================
# ROUTE 1: Home Page
# ============================================================================

@app.route('/')
def index():
    """
    This function runs when someone visits your website.
    It shows the main page (index.html).
    """
    return render_template('index.html')


# ============================================================================
# ROUTE 2: File Analysis API
# ============================================================================

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """
    This function runs when someone uploads a file.
    
    Steps:
    1. Save the uploaded file
    2. Calculate its hash
    3. Identify file type
    4. Check VirusTotal
    5. Return all results as JSON
    """
    
    # Check if a file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Check if filename is empty
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Save the uploaded file
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # STEP 1: Calculate hash
        file_hash = calculate_sha256(filepath)
        
        # STEP 2: Identify file type
        file_type = identify_file_type(filepath)
        
        # STEP 3: Check VirusTotal
        vt_result = check_virustotal(file_hash)
        
        # STEP 4: Prepare response
        result = {
            'filename': filename,
            'file_type': file_type,
            'sha256': file_hash,
            'virustotal': vt_result
        }
        
        # STEP 5: Delete the uploaded file (for security)
        os.remove(filepath)
        
        # Return results as JSON
        return jsonify(result)
        
    except Exception as e:
        # If anything goes wrong, return error
        return jsonify({'error': str(e)}), 500


# ============================================================================
# RUN THE APPLICATION
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 File Identifier & Malware Checker is starting...")
    print("="*60)
    print("\n📋 Instructions:")
    print("1. Make sure you've added your VirusTotal API key to .env file")
    print("2. Open your browser and go to: http://127.0.0.1:5001")
    print("3. Upload a file to analyze it!")
    print("\n⚠️  Press CTRL+C to stop the server\n")
    
  
    app.run(debug=True, host='0.0.0.0', port=5001)