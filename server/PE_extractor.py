import os
import hashlib
import math
import numpy as np
import tempfile
import pefile
from typing import List, Dict, Any, Optional
import json

class PESectionExtractor:
    """
    Securely extracts sections from PE files (EXE, DLL, etc.) using static analysis
    without executing any code from the file.
    """
    
    def __init__(self):
        """Initialize the extractor."""
        pass
    
    def _calculate_chi2(self, data: bytes) -> float:
        """
        Calculate Chi-Square value for the byte distribution in the data.
        
        Args:
            data: Raw bytes from a PE section
            
        Returns:
            Chi-Square value as a float
        """
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = np.zeros(256, dtype=np.int32)
        for b in data:
            byte_counts[b] += 1
        
        # Expected frequency in a uniform distribution
        expected = len(data) / 256
        
        # Calculate chi-square
        chi2 = 0.0
        for count in byte_counts:
            if expected > 0:
                chi2 += (count - expected) ** 2 / expected
                
        return float(chi2)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of the data.
        
        Args:
            data: Raw bytes from a PE section
            
        Returns:
            Entropy value between 0 and 8 as a float
        """
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = np.zeros(256, dtype=np.int32)
        for b in data:
            byte_counts[b] += 1
            
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
                
        return round(entropy, 2)
    
    def _get_section_flags(self, section) -> str:
        """
        Get human-readable flags for a PE section.
        
        Args:
            section: A pefile section object
            
        Returns:
            String representation of the section's permissions
        """
        flags = ""
        
        if section.IMAGE_SCN_MEM_READ:
            flags += "r"
        else:
            flags += "-"
            
        if section.IMAGE_SCN_MEM_WRITE:
            flags += "w"
        else:
            flags += "-"
            
        if section.IMAGE_SCN_MEM_EXECUTE:
            flags += "x"
        else:
            flags += "-"
            
        return flags
    
    def _calculate_md5(self, data: bytes) -> str:
        """
        Calculate MD5 hash of the data.
        
        Args:
            data: Raw bytes from a PE section
            
        Returns:
            MD5 hash as a string
        """
        return hashlib.md5(data).hexdigest()
    
    def extract_sections(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Safely extract section information from a PE file.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            List of dictionaries containing section information
        """
        sections = []
        
        try:
            # Using pefile to safely parse the PE file without execution
            pe = pefile.PE(file_path, fast_load=True)
            
            for section in pe.sections:
                # Extract section name (clean it up)
                try:
                    name = section.Name.decode().rstrip('\x00')
                except UnicodeDecodeError:
                    # Handle non-ASCII section names
                    name = str(section.Name).encode('hex')
                
                # Extract raw data safely
                data = section.get_data()
                
                # Build section info dictionary
                section_info = {
                    "name": name,
                    "chi2": round(self._calculate_chi2(data), 2),
                    "virtual_address": section.VirtualAddress,
                    "flags": self._get_section_flags(section),
                    "raw_size": section.SizeOfRawData,
                    "entropy": self._calculate_entropy(data),
                    "virtual_size": section.Misc_VirtualSize,
                    "md5": self._calculate_md5(data)
                }
                
                sections.append(section_info)
            
            pe.close()
            
        except Exception as e:
            # Log the error but don't expose details to user
            print(f"Error extracting sections: {str(e)}")
            # Return empty list if extraction fails
            return []
            
        return sections

    def extract_to_json(self, file_path: str) -> str:
        """
        Extract PE sections and return as a JSON string.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            JSON string containing section information
        """
        sections = self.extract_sections(file_path)
        return json.dumps(sections, indent=4)

if __name__ == "__main__":
    extractor = PESectionExtractor()
    exe_path = "./ques1.exe"
    
    print("Extracting sections from:", exe_path)
    sections = extractor.extract_sections(exe_path)
    
    print("\nExtracted Sections:")
    for section in sections:
        print(section)
    
    json_data = extractor.extract_to_json(exe_path)
    print("\nExtracted Sections as JSON:")
    print(json_data)

