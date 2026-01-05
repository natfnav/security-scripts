#!/usr/bin/env python3
"""
File Integrity Checker

The contents of this script validates whether two files are the same by comparing their
hash values.
"""

import sys
import hashlib
 
# Function that processes and returns the hash of a file
def hashfile(file):
    # Arbitrary fixed buffer size (in bytes)
    BUF_SIZE = 65536 
 
    # Initialize SHA-256 hashing algorithm
    sha256 = hashlib.sha256()
 
    # Open file for reading in binary mode
    with open(file, 'rb') as f:
        while True:
            # Read data from file
            data = f.read(BUF_SIZE)

            # Stop reading if EOF is reached
            if not data:
                break
     
            # Pass data to SHA-256 algorithm
            sha256.update(data)

    # Return hash value in hexadecimal format
    return sha256.hexdigest()

# Main function
if __name__ == "__main__":
    # Obtain hash of two files provided as cmd line arguments
    f1_hash = hashfile(sys.argv[1])
    f2_hash = hashfile(sys.argv[2])
 
    # Check if the two hashes match or not
    if f1_hash == f2_hash:
        print("Both files are same")
        print(f"Hash: {f1_hash}")
    else:
        print("Files are different!")
        print(f"Hash of File 1: {f1_hash}")
        print(f"Hash of File 2: {f2_hash}")