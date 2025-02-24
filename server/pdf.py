import os
import hashlib
import math
import re
import json
import struct
import magic
import zlib
import logging
import multiprocessing
import shutil
from collections import defaultdict
from datetime import datetime
import numpy as np
import pandas as pd
import pdfplumber
from PyPDF2 import PdfReader
from pathlib import Path
import tldextract
import warnings
import statistics
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PDFMalwareAnalyzer:
    def __init__(self):
        self.action_objects = {
            '/JavaScript', '/Launch', '/SubmitForm', '/URI', '/GoTo', 
            '/OpenAction', '/AA', '/JS', '/Sound', '/Movie'
        }
        
        self.suspicious_fonts = {
            'ZapfDingbats', 'Wingdings', 'Symbol', 'MZZZZZ+', 
            'ABCDEF+', '######+', 'Identity-H', 'Identity-V'
}
        
        self.suspicious_js_patterns = {
            'eval': rb'eval\s*\(',
            'unescape': rb'unescape\s*\(',
            'fromCharCode': rb'(?:String\.)?fromCharCode',
            'shellcode': rb'(?:shell|shell_?code)',
            'heap_spray': rb'heap[_\s]spray',
            'function_def': rb'function\s*\([^)]*\)\s*{[^}]*}',
            'suspicious_vars': rb'var\s+[a-zA-Z_$][0-9a-zA-Z_$]*\s*=\s*unescape',
            'suspicious_arrays': rb'var\s+[a-zA-Z_$][0-9a-zA-Z_$]*\s*=\s*new\s+Array\(\d+\)',
            'document_write': rb'document\.write\s*\(',
            'hex_encoded': rb'\\x[0-9a-fA-F]{2}',
            'base64_payloads': rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            'obfuscated_strings': rb'(?:\+\[\]|!+\[\]|\[\]\!|\"\"\+\+)'
        }
        
        self.suspicious_strings = {
            'malware_keywords': rb'(?i)(exploit|backdoor|trojan|virus|malware|payload|rootkit)',
            'suspicious_commands': rb'(?i)(cmd\.exe|powershell|rundll32|wscript)',
            'network_indicators': rb'(?i)(http:|https:|ftp:|socket|connect)',
            'registry_access': rb'(?i)(HKEY_|RegRead|RegWrite)',
            'system_commands': rb'(?i)(system32|syswow64|temp\\|%temp%)',
            'command_injection': rb'(?i)(%COMSPEC%|%WINDIR%|\bexec\b|\bexecute\b)'
        }

    def analyze_pdf(self, pdf_path):
        """
        Analyze a PDF file and extract features safely.
        Returns a dictionary of features or None if analysis fails.
        """
        try:
            with open(pdf_path, 'rb') as f:
                content = f.read()
                
            # Create a base features dictionary
            features = {}
            
            # List of feature extraction methods and their corresponding names
            extraction_methods = [
                (self.get_basic_features, 'basic'),
                (self._check_encryption, 'encryption'),
                (self._analyze_metadata, 'metadata'),
                (self.analyze_pdf_structure, 'structure'),
                (self._validate_xref_table, 'xref'),
                (self.analyze_objects, 'objects'),
                (self._extract_embedded_scripts, 'scripts'),
                (self.analyze_actions_and_javascript, 'javascript'),
                (self.analyze_fonts, 'fonts'),
                (self.analyze_streams, 'streams'),
                (self.analyze_urls, 'urls'),
                (self.analyze_embedded_files, 'embedded_files')
            ]
            
            # Safely execute each feature extraction method
            for method, prefix in extraction_methods:
                try:
                    method_features = method(content)
                    if method_features:
                        # Prefix all keys from this method to avoid collisions
                        prefixed_features = {
                            f"{prefix}_{k}" if not k.startswith(prefix) else k: v 
                            for k, v in method_features.items()
                        }
                        # Create a copy of the dictionary for safe updating
                        features.update(prefixed_features.copy())
                except Exception as e:
                    logging.warning(f"Error in {method.__name__} for {pdf_path}: {str(e)}")
                    # Continue processing other features even if one method fails
                    continue
            
            return features if features else None
            
        except Exception as e:
            logging.error(f"Error analyzing {pdf_path}: {str(e)}")
            return None


    def get_basic_features(self, content):
        """Extract basic file features"""
        features = {
            'file_size': len(content),
            'file_entropy': self._shannon_entropy(content),
            'hash_value': hashlib.sha256(content).hexdigest(),
        }
        
        # Calculate file magic number
        mime = magic.Magic(mime=True)
        features['mime_type'] = mime.from_buffer(content)
        
        return features
    
    def _check_suspicious_trailer(self, trailer_data):
        """
        Analyze PDF trailer for suspicious characteristics
        
        Args:
            trailer_data (bytes): Raw trailer data
            
        Returns:
            bool: True if suspicious characteristics found, False otherwise
        """
        suspicious = False
        
        # Check for encryption that's not properly declared
        if rb'/Encrypt' in trailer_data and not re.search(rb'/Encrypt\s*\d+\s+\d+\s+R', trailer_data):
            suspicious = True
        
        # Check for invalid /Root reference
        root_ref = re.search(rb'/Root\s*(\d+\s+\d+)\s+R', trailer_data)
        if not root_ref:
            suspicious = True
        
        # Check for multiple /Root or /Info references
        if len(re.findall(rb'/Root', trailer_data)) > 1 or len(re.findall(rb'/Info', trailer_data)) > 1:
            suspicious = True
        
        # Check for suspicious dictionary entries
        suspicious_entries = [rb'/AA', rb'/JavaScript', rb'/JS', rb'/Launch', rb'/SubmitForm', rb'/ImportData']
        if any(entry in trailer_data for entry in suspicious_entries):
            suspicious = True
        
        # Check for unusually large /Prev values
        prev_match = re.search(rb'/Prev\s+(\d+)', trailer_data)
        if prev_match and int(prev_match.group(1)) > 1000000:  # Suspicious if > 1MB offset
            suspicious = True
        
        return suspicious
    

    def _validate_pdf_structure(self, content):
        """
        Validate PDF document structure and return number of structural errors
        
        Args:
            content (bytes): Raw PDF content
            
        Returns:
            int: Number of structural errors found
        """
        error_count = 0
        
        # Check PDF header
        if not content.startswith(b'%PDF-'):
            error_count += 1
        
        # Check for EOF marker
        if not content.rstrip().endswith(b'%%EOF'):
            error_count += 1
        
        # Validate object structure
        obj_starts = re.finditer(rb'\d+\s+\d+\s+obj', content)
        for obj_start in obj_starts:
            # Find corresponding endobj
            start_pos = obj_start.start()
            obj_content = content[start_pos:start_pos+10000]  # Look within reasonable range
            if b'endobj' not in obj_content:
                error_count += 1
        
        # Check stream/endstream pairs
        stream_count = len(re.findall(rb'stream[\r\n]', content))
        endstream_count = len(re.findall(rb'endstream', content))
        if stream_count != endstream_count:
            error_count += 1
        
        # Validate xref table structure
        xref_positions = [m.start() for m in re.finditer(rb'xref', content)]
        for pos in xref_positions:
            # Check if xref is followed by valid entries
            xref_section = content[pos:pos+1000]  # Look at reasonable chunk after xref
            if not re.search(rb'xref\s*\n\d+\s+\d+\s*\n', xref_section):
                error_count += 1
        
        # Check for proper trailer
        trailer_count = len(re.findall(rb'trailer', content))
        if trailer_count == 0:
            error_count += 1
        elif trailer_count > 1:
            # Multiple trailers are allowed for incremental updates, verify they're properly structured
            trailer_positions = [m.start() for m in re.finditer(rb'trailer', content)]
            for pos in trailer_positions:
                trailer_section = content[pos:pos+1000]
                if not re.search(rb'trailer\s*<<.*?>>', trailer_section, re.DOTALL):
                    error_count += 1
        
        # Validate cross-reference table
        if b'xref' in content:
            xref_table = re.search(rb'xref\s*\n(.*?)\s*trailer', content, re.DOTALL)
            if xref_table:
                xref_entries = xref_table.group(1).split(b'\n')
                for entry in xref_entries[1:]:  # Skip the first line (subsection header)
                    if entry and not re.match(rb'\d{10}\s+\d{5}\s+[fn]\s*$', entry):
                        error_count += 1
        
        return error_count
    
    def _check_reverse_order(self, content):
        """Check for reverse order objects in the PDF"""
        obj_matches = re.findall(rb'(\d+)\s+(\d+)\s+obj', content)
        obj_order = [(int(obj_id), int(gen_num)) for obj_id, gen_num in obj_matches]
        
        # Check if the objects are in reverse order
        reverse_order = obj_order != sorted(obj_order, reverse=True)
        
        return reverse_order
    
    def analyze_fonts(self, content):
        """Analyze font usage and detect rare/suspicious fonts"""
        features = {}
        font_matches = re.findall(rb'/Font\s*<<(.+?)>>', content, re.DOTALL)
        fonts = []
        
        for match in font_matches:
            font_names = re.findall(rb'/BaseFont\s*/([^\s/]+)', match)
            fonts.extend(font_names)
        
        features['total_fonts'] = len(fonts)
        features['suspicious_fonts'] = sum(1 for f in fonts if any(sf in f.decode('utf-8', 'ignore') 
                                        for sf in self.suspicious_fonts))
        features['rare_font_count'] = len(set(fonts))
        features['pdf_version_anomaly'] = self._check_version_anomaly(content)
        
        return features
    


    def _analyze_object_streams(self, content):
        """
        Analyze object streams safely.
        """
        features = {
            'total_streams': 0,
            'avg_stream_size': 0,
            'max_stream_size': 0,
            'avg_stream_entropy': 0,
            'max_stream_entropy': 0,
            'high_entropy_streams': 0
        }
        
        try:
            # Collect all streams first
            stream_markers = list(re.finditer(rb'stream\r?\n', content))
            endstream_markers = list(re.finditer(rb'endstream', content))
            
            if not stream_markers or not endstream_markers:
                return features
                
            # Process all streams
            streams_data = []
            for start, end in zip(stream_markers, endstream_markers):
                try:
                    stream_content = content[start.end():end.start()]
                    size = len(stream_content)
                    entropy = self._shannon_entropy(stream_content)
                    streams_data.append((size, entropy))
                except Exception:
                    continue
                    
            if streams_data:
                sizes, entropies = zip(*streams_data)
                features['total_streams'] = len(streams_data)
                features['avg_stream_size'] = sum(sizes) / len(sizes)
                features['max_stream_size'] = max(sizes)
                features['avg_stream_entropy'] = sum(entropies) / len(entropies)
                features['max_stream_entropy'] = max(entropies)
                features['high_entropy_streams'] = sum(1 for e in entropies if e > 7.0)
                
            return features
            
        except Exception as e:
            logging.warning(f"Error in stream analysis: {str(e)}")
            return features
    
    def _count_action_triggers(self, content):
        """Count PDF action triggers"""
        triggers = {
            b'/OpenAction': 0,
            b'/AA': 0,  # Additional Actions
            b'/Launch': 0,
            b'/JavaScript': 0,
            b'/SubmitForm': 0,
            b'/ImportData': 0
        }
        
        for trigger in triggers:
            triggers[trigger] = content.count(trigger)
        
        return sum(triggers.values())

    def analyze_pdf_structure(self, content):
        """Analyze PDF structure integrity"""
        features = {}
        
        # Header validation
        features['valid_header'] = int(content.startswith(b'%PDF-'))
        features['pdf_version'] = self._extract_pdf_version(content)
        
        # EOF marker
        features['valid_eof'] = int(b'%%EOF' in content[-1024:])
        
        # XRef table analysis
        xref_features = self._validate_xref_table(content)
        features.update(xref_features)
        features['object_stream_mismatches'] = self._check_stream_mismatches(content)
        features['high_entropy_objects'] = self._count_high_entropy_objects(content)
        # Reverse order objects
        features['reverse_order_objects'] = self._check_reverse_order(content)
        
        # Trailer analysis
        trailer_features = self._analyze_trailer(content)
        features.update(trailer_features)
        
        # Structure validation
        features['structure_errors'] = self._validate_pdf_structure(content)
        
        return features
    
    def _calculate_object_graph_complexity(self, content):
        """
        Calculate the complexity of the PDF object reference graph.
        Higher complexity may indicate malicious obfuscation.
        
        Args:
            content (bytes): Raw PDF content
        
        Returns:
            float: Complexity score between 0 and 1
        """
        # Extract all object references
        obj_refs = re.findall(rb'(\d+)\s+(\d+)\s+R', content)
        if not obj_refs:
            return 0.0
        
        # Build adjacency list for object references
        graph = defaultdict(set)
        for ref_obj, gen_num in obj_refs:
            # Find the object that contains this reference
            containing_obj = None
            for match in re.finditer(rb'(\d+)\s+\d+\s+obj', content):
                obj_start = match.start()
                obj_id = match.group(1)
                # Find corresponding endobj
                obj_end = content.find(b'endobj', obj_start)
                if obj_end == -1:
                    continue
                # Check if reference is within this object
                if obj_start < content.find(ref_obj, obj_start, obj_end) < obj_end:
                    containing_obj = obj_id
                    break
            
            if containing_obj:
                graph[containing_obj].add(ref_obj)
        
        if not graph:
            return 0.0
        
        # Calculate complexity metrics
        total_objects = len(set(ref for refs in graph.values() for ref in refs) | set(graph.keys()))
        if total_objects == 0:
            return 0.0
            
        # Calculate reference density
        total_refs = sum(len(refs) for refs in graph.values())
        max_possible_refs = total_objects * (total_objects - 1)  # Maximum possible edges in a directed graph
        density = total_refs / max_possible_refs if max_possible_refs > 0 else 0
        
        # Calculate average reference chain length
        chain_lengths = []
        visited = set()
        
        def dfs(obj_id, current_length):
            if obj_id in visited:
                chain_lengths.append(current_length)
                return
            visited.add(obj_id)
            for ref in graph[obj_id]:
                dfs(ref, current_length + 1)
            if not graph[obj_id]:  # Leaf node
                chain_lengths.append(current_length)
        
        for start_obj in graph.keys():
            if start_obj not in visited:
                dfs(start_obj, 0)
        
        avg_chain_length = statistics.mean(chain_lengths) if chain_lengths else 0
        max_normal_chain = 5  # Expected maximum chain length in normal PDFs
        chain_complexity = min(avg_chain_length / max_normal_chain, 1.0)
        
        # Combine metrics with weights
        complexity_score = 0.7 * density + 0.3 * chain_complexity
        
        return min(complexity_score, 1.0)

    def analyze_objects(self, content):
        """
        Analyze PDF objects with fixed dictionary handling.
        """
        features = {
            'total_objects': 0,
            'object_streams': 0,
            'object_graph_complexity': 0.0,
            'incremental_updates': 0,
            'total_streams': 0,
            'avg_stream_size': 0,
            'max_stream_size': 0,
            'avg_stream_entropy': 0,
            'max_stream_entropy': 0,
            'high_entropy_streams': 0
        }
        
        try:
            # Count objects first
            obj_matches = list(re.finditer(rb'\d+\s+\d+\s+obj', content))
            features['total_objects'] = len(obj_matches)
            features['object_streams'] = len(re.findall(rb'/ObjStm', content))
            features['incremental_updates'] = max(0, content.count(b'%%EOF') - 1)
            
            # Calculate complexity
            try:
                features['object_graph_complexity'] = self._calculate_object_graph_complexity(content)
            except Exception:
                pass
                
            # Analyze streams
            stream_features = self._analyze_object_streams(content)
            if stream_features:
                features.update(stream_features)
                
            return features
            
        except Exception as e:
            logging.warning(f"Error in object analysis: {str(e)}")
            return features

    def analyze_actions_and_javascript(self, content):
        """Comprehensive analysis of actions and JavaScript content"""
        features = defaultdict(int)
        
        # Count action objects
        for action in self.action_objects:
            features[f'action_{action.lower()[1:]}'] = content.count(action.encode())
        
        # JavaScript analysis
        js_features = self._analyze_javascript(content)
        features.update(js_features)
        
        # Action triggers
        features['action_triggers'] = self._count_action_triggers(content)
        
        return features
    
    def _extract_streams(self, content):
        """Extract all streams from PDF content"""
        streams = []
        stream_markers = list(re.finditer(rb'stream\r?\n', content))
        endstream_markers = list(re.finditer(rb'endstream', content))
        
        if len(stream_markers) != len(endstream_markers):
            return []
            
        for start, end in zip(stream_markers, endstream_markers):
            try:
                stream_content = content[start.end():end.start()]
                # Try to decompress if possible
                try:
                    decompressed = self._decompress_stream(stream_content)
                    streams.append(decompressed)
                except:
                    streams.append(stream_content)
            except Exception as e:
                logging.debug(f"Error extracting stream content: {str(e)}")
                continue
                
        return streams
    

    def _analyze_stream_contents(self, streams):
        """Analyze contents of PDF streams for suspicious patterns"""
        suspicious_count = 0
        
        for stream in streams:
            # Check for JavaScript
            if b'/JavaScript' in stream or b'/JS' in stream:
                suspicious_count += 1
                
            # Check for executable content
            if b'MZ' in stream or b'%PDF' in stream:
                suspicious_count += 1
                
            # Check for shellcode patterns
            if re.search(rb'(?:\\x[0-9a-fA-F]{2}){10,}', stream):
                suspicious_count += 1
                
            # Check for encoded content
            if re.search(rb'base64|hex', stream, re.I):
                suspicious_count += 1
        
        return suspicious_count



    def analyze_streams(self, content):
        """
        Analyze streams with fixed dictionary handling.
        """
        features = {}
        try:
            streams = self._extract_streams(content)
            if streams:
                # Calculate all metrics first
                entropies = [self._shannon_entropy(s) for s in streams]
                
                # Then assign to dictionary
                features['stream_entropy_avg'] = float(np.mean(entropies))
                features['stream_entropy_std'] = float(np.std(entropies))
                features['high_entropy_streams'] = sum(1 for e in entropies if e > 7.0)
                features['total_streams'] = len(streams)
                features['suspicious_stream_content'] = self._analyze_stream_contents(streams)
                
        except Exception as e:
            logging.warning(f"Error in stream analysis: {str(e)}")
            
        return dict(features)  # 

    def _count_suspicious_urls(self, urls):
        """Count suspicious URLs in PDF"""
        suspicious_count = 0
        
        for url in urls:
            try:
                url_str = url.decode('utf-8', 'ignore').lower()
                
                # Extract domain
                extracted = tldextract.extract(url_str)
                domain = f"{extracted.domain}.{extracted.suffix}"
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    r'\.(?:ru|cn|tk|pw|cc|xyz|top)$',  # Suspicious TLDs
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
                    r'bit\.ly|goo\.gl|t\.co|tinyurl',  # URL shorteners
                    r'download|update|patch|install',  # Action words
                    r'[0-9a-f]{32}',  # MD5-like strings
                    r'%[0-9a-f]{2}',  # URL encoding
                    r'=\s*(?:eval|exec|system)',  # Code execution
                ]
                
                if any(re.search(pattern, url_str) for pattern in suspicious_patterns):
                    suspicious_count += 1
                    
            except Exception as e:
                logging.debug(f"Error analyzing URL: {str(e)}")
                continue
        
        return suspicious_count

    def analyze_urls(self, content):
        """Enhanced URL analysis"""
        features = defaultdict(int)
        urls = re.findall(rb'(?i)https?://[^\s<>"]+|www\.[^\s<>"]+', content)
        
        features.update({
            'total_urls': len(urls),
            'unique_urls': len(set(urls)),
            'suspicious_urls': self._count_suspicious_urls(urls)
        })
        
        return features

    def analyze_embedded_files(self, content):
        features = defaultdict(int)
        signatures = {
            b'MZ': 'exe',
            b'%PDF': 'pdf',
            b'\xD0\xCF\x11\xE0': 'ole',
            b'PK\x03\x04': 'zip',
            b'\xFF\xD8\xFF': 'jpg',
            b'\x89PNG': 'png'
        }
        
        for sig, ftype in signatures.items():
            features[f'embedded_{ftype}'] = content.count(sig)
        
        features['embedded_executable_files'] = features['embedded_exe'] + features['embedded_ole']
        return features
    
    def _check_metadata_anomalies(self, metadata):
        """Check for anomalies in PDF metadata"""
        anomaly_count = 0
        date_patterns = re.findall(rb'\(D:[^)]+\)', metadata)
        for date in date_patterns:
            if not self._is_valid_pdf_date(date):
                anomaly_count += 1
        
        suspicious_producers = [rb'PDFLite', rb'TCPDF', rb'Scribus', rb'OpenOffice']
        for prod in suspicious_producers:
            if prod in metadata:
                anomaly_count += 1
        
        return anomaly_count

    def _is_valid_pdf_date(self, date_str):
        """Validate PDF date format"""
        try:
            pattern = rb'\(D:(\d{14}[+-Z]?\d{2,4}\'?\d{2,4}\'?)\)'
            return bool(re.match(pattern, date_str))
        except:
            return False

    def _shannon_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
            
        entropy = 0
        data_len = len(data)
        for x in range(256):
            p_x = data.count(bytes([x])) / data_len
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def _extract_pdf_version(self, content):
        """Extract PDF version from header"""
        match = re.search(rb'%PDF-(\d+\.\d+)', content)
        return match.group(1).decode() if match else "0.0"

    def _validate_xref_table(self, content):
        """Comprehensive validation of cross-reference table"""
        features = {
            'xref_errors': 0,
            'xref_consistency': True,
            'xref_structure': True
        }
        
        # Find all xref sections
        xref_sections = re.finditer(rb'xref\s*\n(\d+\s+\d+\s*\n(?:\d{10}\s+\d{5}\s+[fn]\s*\n)*)', content)
        
        for section in xref_sections:
            section_data = section.group(1)
            
            # Check entry format
            entries = re.finditer(rb'(\d{10}\s+\d{5}\s+[fn])\s*\n', section_data)
            for entry in entries:
                entry_str = entry.group(1)
                
                # Validate entry format
                if not re.match(rb'^\d{10}\s+\d{5}\s+[fn]$', entry_str):
                    features['xref_errors'] += 1
                
                # Check offset validity
                offset = int(entry_str[:10])
                if offset >= len(content):
                    features['xref_consistency'] = False
                
                # Check for proper object references
                if entry_str[-1:] == b'n':
                    obj_check = content[offset:offset+20]
                    if not re.match(rb'\d+\s+\d+\s+obj', obj_check):
                        features['xref_structure'] = False
        
        return features

    def _analyze_trailer(self, content):
        """Analyze PDF trailer"""
        features = {}
        trailer_data = re.findall(rb'trailer\s*<<(.+?)>>', content, re.DOTALL)
        
        if trailer_data:
            features['trailer_count'] = len(trailer_data)
            features['suspicious_trailer'] = self._check_suspicious_trailer(trailer_data[0])
        
        return features
    


    def _check_stream_mismatches(self, content):
        """Check for mismatches in object streams"""
        stream_counts = len(re.findall(rb'stream\r?\n', content))
        endstream_counts = len(re.findall(rb'endstream', content))
        return abs(stream_counts - endstream_counts)

    def _count_high_entropy_objects(self, content):
        """Count objects with high entropy"""
        objects = re.findall(rb'\d+\s+\d+\s+obj.*?endobj', content, re.DOTALL)
        return sum(1 for obj in objects if self._shannon_entropy(obj) > 7.0)

    def _check_version_anomaly(self, content):
        """Check for PDF version anomalies"""
        version_match = re.search(rb'%PDF-(\d+\.\d+)', content)
        if not version_match:
            return True
        version = float(version_match.group(1))
        return version > 1.7 or version < 1.0


    def _check_encryption(self, content):
        """Enhanced encryption parameter analysis"""
        features = {
            'is_encrypted': False,
            'encryption_method': None,
            'encryption_version': None,
            'encryption_key_length': None
        }
        
        # Check for encryption dictionary
        encrypt_dict = re.search(rb'/Encrypt\s*<<(.+?)>>', content, re.DOTALL)
        if encrypt_dict:
            features['is_encrypted'] = True
            dict_content = encrypt_dict.group(1)
            
            # Extract encryption method
            if rb'/Filter' in dict_content:
                filter_match = re.search(rb'/Filter\s*/(\w+)', dict_content)
                if filter_match:
                    features['encryption_method'] = filter_match.group(1).decode('utf-8', 'ignore')
            
            # Extract version (V)
            if rb'/V' in dict_content:
                v_match = re.search(rb'/V\s+(\d+)', dict_content)
                if v_match:
                    features['encryption_version'] = int(v_match.group(1))
            
            # Extract key length (Length)
            if rb'/Length' in dict_content:
                length_match = re.search(rb'/Length\s+(\d+)', dict_content)
                if length_match:
                    features['encryption_key_length'] = int(length_match.group(1))
        
        return features

    def _analyze_metadata(self, content):
        """Comprehensive metadata analysis"""
        features = {}
        
        # Extract metadata dictionary
        metadata = re.search(rb'/Metadata\s*<<(.+?)>>', content, re.DOTALL)
        if metadata:
            metadata_content = metadata.group(1)
            
            # Check creation and modification dates
            features['creation_date_anomaly'] = self._check_date_anomaly(metadata_content, rb'/CreationDate')
            features['mod_date_anomaly'] = self._check_date_anomaly(metadata_content, rb'/ModDate')
            
            # Check producer software
            features['suspicious_producer'] = self._check_suspicious_producer(metadata_content)
            
            # Check for XMP metadata consistency
            features['xmp_metadata_mismatch'] = self._check_xmp_consistency(content, metadata_content)
            
            # Additional metadata checks
            features['metadata_stream_anomaly'] = self._check_metadata_stream(content)
        
        return features
    

    def _check_date_anomaly(self, metadata, date_field):
        """Check for suspicious dates in metadata"""
        date_match = re.search(date_field + rb'\s*\((D:[^)]+)\)', metadata)
        if date_match:
            date_str = date_match.group(1)
            try:
                # Check for future dates
                if b'9999' in date_str:
                    return True
                # Check for very old dates
                if b'19' in date_str[:4]:
                    return True
                return False
            except:
                return True
        return False


    def _check_suspicious_producer(self, metadata):
        """Check for suspicious PDF producer software"""
        suspicious_producers = [
            rb'PDFLite', rb'TCPDF', rb'Scribus', rb'OpenOffice',
            rb'PDF\s*Generator', rb'Unknown\s*Producer'
        ]
        
        producer_match = re.search(rb'/Producer\s*\(([^)]+)\)', metadata)
        if producer_match:
            producer = producer_match.group(1)
            return any(re.search(pattern, producer) for pattern in suspicious_producers)
        return False

    def _check_xmp_consistency(self, content, metadata):
        """Check consistency between document info and XMP metadata"""
        # Extract document info
        info_dict = re.search(rb'/Info\s*(\d+\s+\d+\s+R)', content)
        xmp_stream = re.search(rb'<\?xpacket[^>]*\?>(.*?)<\?xpacket\s+end', content, re.DOTALL)
        
        if info_dict and xmp_stream:
            # Compare basic metadata fields
            doc_title = re.search(rb'/Title\s*\(([^)]+)\)', metadata)
            xmp_title = re.search(rb'<dc:title>[^<]*<rdf:Alt>[^<]*<rdf:li[^>]*>([^<]+)', xmp_stream.group(1))
            
            if doc_title and xmp_title:
                return doc_title.group(1) != xmp_title.group(1)
        
        return False
    
    def _check_metadata_stream(self, content):
        """Check for anomalies in metadata stream"""
        metadata_stream = re.search(rb'/Metadata\s*\d+\s+\d+\s+R.*?stream\s*(.*?)\s*endstream', content, re.DOTALL)
        if metadata_stream:
            stream_data = metadata_stream.group(1)
            try:
                decompressed = self._decompress_stream(stream_data)
                # Check for suspicious patterns in metadata stream
                suspicious_patterns = [
                    rb'<script', rb'javascript:', rb'eval\(', 
                    rb'\\x[0-9a-fA-F]{2}', rb'%[0-9a-fA-F]{2}'
                ]
                return any(pattern in decompressed.lower() for pattern in suspicious_patterns)
            except:
                return True
        return False


    def _analyze_javascript(self, content):
        """Advanced JavaScript analysis"""
        features = {}
        js_content = self._extract_javascript(content)
        
        if js_content:
            # Basic stats
            features['js_size'] = len(js_content)
            features['js_entropy'] = self._shannon_entropy(js_content)
            
            # Pattern matching
            for name, pattern in self.suspicious_js_patterns.items():
                features[f'js_{name}'] = len(re.findall(pattern, js_content))
            
            # Obfuscation detection
            features['js_obfuscation_score'] = self._calculate_obfuscation_score(js_content)
            
            # Shellcode detection
            features['shellcode_likelihood'] = self._detect_shellcode(js_content)
        
        return features

    def _extract_javascript(self, content):
        """Extract JavaScript content from PDF"""
        js_content = b''
        
        # Direct JavaScript
        js_matches = re.findall(rb'/JavaScript\s*<<(.+?)>>', content, re.DOTALL)
        js_content += b''.join(js_matches)
        
        # JavaScript in streams
        stream_matches = re.findall(rb'stream\s*(.*?)\s*endstream', content, re.DOTALL)
        for stream in stream_matches:
            try:
                decompressed = self._decompress_stream(stream)
                if b'/JavaScript' in decompressed:
                    js_content += decompressed
            except:
                continue
        
        return js_content

    def _calculate_obfuscation_score(self, js_content):
        """Calculate JavaScript obfuscation score"""
        indicators = {
            'eval_count': len(re.findall(rb'eval\s*\(', js_content)),
            'hex_strings': len(re.findall(rb'\\x[0-9a-fA-F]{2}', js_content)),
            'long_strings': len(re.findall(rb'"[^"]{1000,}"', js_content)),
            'string_concatenation': len(re.findall(rb'\+\s*["\']', js_content)),
            'unicode_escape': len(re.findall(rb'\\u[0-9a-fA-F]{4}', js_content))
        }
        
        # Calculate weighted score
        weights = {'eval_count': 0.3, 'hex_strings': 0.2, 'long_strings': 0.2,
                'string_concatenation': 0.15, 'unicode_escape': 0.15}
        
        score = sum(min(count * weights[key], 1.0) for key, count in indicators.items())
        return min(score, 1.0)

    def _detect_shellcode(self, content):
        """Detect potential shellcode"""
        shellcode_patterns = [
            rb'\\x([0-9a-fA-F]{2}){8,}',
            rb'(%u[0-9a-fA-F]{4}){4,}',
            rb'(?:0x[0-9a-fA-F]{2},?\s*){8,}'
        ]
        
        score = 0
        for pattern in shellcode_patterns:
            matches = re.findall(pattern, content)
            score += min(len(matches), 10) / 10
        
        return min(score, 1.0)


    def _extract_embedded_scripts(self, content):
        """Extract and analyze all types of embedded scripts"""
        script_features = {
            'total_scripts': 0,
            'script_types': defaultdict(int),
            'suspicious_scripts': 0
        }
        
        # JavaScript
        js_scripts = re.findall(rb'/JavaScript\s*<<.*?>>', content, re.DOTALL)
        script_features['script_types']['javascript'] = len(js_scripts)
        
        # ActionScript
        as_scripts = re.findall(rb'/AS\s*<<.*?>>', content, re.DOTALL)
        script_features['script_types']['actionscript'] = len(as_scripts)
        
        # Form calculations and validations
        form_scripts = re.findall(rb'/AA\s*<<.*?/C\s*<<.*?>>', content, re.DOTALL)
        script_features['script_types']['form_scripts'] = len(form_scripts)
        
        script_features['total_scripts'] = sum(script_features['script_types'].values())
        
        # Analyze scripts for suspicious content
        all_scripts = js_scripts + as_scripts + form_scripts
        for script in all_scripts:
            if self._analyze_script_content(script):
                script_features['suspicious_scripts'] += 1
        
        return script_features


    def _analyze_script_content(self, script):
        """Analyze script content for suspicious patterns"""
        suspicious_patterns = [
            rb'eval\s*\(', rb'unescape\s*\(', rb'String\.fromCharCode',
            rb'document\.write', rb'getAnnots', rb'this\.submitForm',
            rb'app\.launchURL', rb'util\.printf', rb'spell\.customDictionaryOpen'
        ]
        
        try:
            decompressed = self._decompress_stream(script)
            return any(pattern in decompressed for pattern in suspicious_patterns)
        except:
            return False




    def _decompress_stream(self, stream):
        """Decompress PDF stream data"""
        try:
            return zlib.decompress(stream)
        except:
            return stream

def process_file(pdf_path, label):
    """Process a single PDF file with improved error handling and result formatting"""
    try:
        analyzer = PDFMalwareAnalyzer()
        features = analyzer.analyze_pdf(pdf_path)
        
        if features is None:
            return None
            
        # Add file path and label
        features['file_path'] = pdf_path
        features['label'] = label
        
        # Move the processed file to the processed directory
        processed_dir = Path('./processed_files')
        processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Get the original filename and create the destination path
        source_path = Path(pdf_path)
        dest_path = processed_dir / source_path.name
        
        # If a file with the same name exists, add a unique suffix
        counter = 1
        while dest_path.exists():
            stem = source_path.stem
            suffix = source_path.suffix
            dest_path = processed_dir / f"{stem}_{counter}{suffix}"
            counter += 1
            
        try:
            shutil.move(str(source_path), str(dest_path))
            logging.info(f"Moved {source_path.name} to processed files directory")
        except Exception as move_error:
            logging.warning(f"Failed to move {source_path.name}: {str(move_error)}")
        
        return features
        
    except Exception as e:
        logging.warning(f"Error processing {pdf_path}: {str(e)}")
        return None



def process_dataset(benign_dir, output_dir):
    """Process a single PDF file and append its features to a CSV file"""
    logging.info("Starting dataset processing...")
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Collect benign files
    benign_files = list(Path(benign_dir).glob('*.pdf'))
    
    if not benign_files:
        raise ValueError("No PDF files found to process")
    
    # Ensure there is only one file
    if len(benign_files) > 1:
        raise ValueError("More than one PDF file found. Please ensure only one file is in the directory.")
    
    # Define all columns we want to capture
    columns = [
        'file_path', 'label',
        # Basic features
        'file_size', 'file_entropy', 'hash_value',
        'mime_type', 'is_encrypted',
        
        # Structure features
        'pdf_version', 'valid_header', 'valid_eof',
        'structure_errors', 'xref_errors', 'xref_consistency',
        'reverse_order_objects', 'object_stream_mismatches',
        'suspicious_trailer', 'object_graph_complexity',
        'incremental_updates', 'high_entropy_objects',
        
        # Script and code features
        'total_scripts', 'suspicious_scripts',
        'js_size', 'js_entropy', 'js_obfuscation_score',
        'shellcode_likelihood',
        
        # Action and JavaScript features
        'action_javascript', 'action_launch', 'action_submitform',
        'action_uri', 'action_goto', 'action_openaction',
        'action_aa', 'action_js', 'action_sound', 'action_movie',
        'action_triggers',
        
        # Embedded content
        'embedded_exe', 'embedded_pdf', 'embedded_ole',
        'embedded_zip', 'embedded_jpg', 'embedded_png',
        'embedded_executable_files',
        
        # Stream analysis
        'total_streams', 'avg_stream_size', 'max_stream_size',
        'avg_stream_entropy', 'max_stream_entropy',
        'high_entropy_streams',
        
        # Font analysis
        'total_fonts', 'suspicious_fonts', 'rare_font_count',
        'pdf_version_anomaly',
        
        # URL analysis
        'total_urls', 'unique_urls', 'suspicious_urls',
        
        # Encryption
        'encryption_method', 'encryption_key_length'
    ]
    
    # Create empty DataFrame with specified columns
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = output_path / f'output.csv'
    json_path = output_path / f'pdf_features_{timestamp}.json'
    
    df = pd.DataFrame(columns=columns)
    df.to_csv(csv_path, index=False)
    
    # Process the single file
    pdf_path = str(benign_files[0])
    try:
        features = process_file(pdf_path, 0)  # Benign = 0
        if features:
            # Create a DataFrame for the current result
            df_result = pd.DataFrame([features])
            # Append the result to the CSV file
            df_result.to_csv(csv_path, mode='a', header=False, index=False)
            logging.info(f"Processed and appended features for {pdf_path}")
    except Exception as e:
        logging.warning(f"Error processing {pdf_path}: {str(e)}")
    
    logging.info(f"Processing completed. Results saved to {csv_path}")
    return csv_path, json_path


def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PDF Malware Feature Extraction')
    parser.add_argument('--benign', required=True, help='Directory containing benign PDFs')
    parser.add_argument('--output', required=True, help='Output directory for results')
    parser.add_argument('--jobs', type=int, default=multiprocessing.cpu_count(),
                       help='Number of parallel jobs')
    
    args = parser.parse_args()
    
    # Validate directories
    if not os.path.isdir(args.benign):
        raise ValueError(f"Directory not found: {args.benign}")
    
    # Set number of processes for parallel processing
    multiprocessing.set_start_method('spawn', force=True)
    
    try:
        csv_path, json_path = process_dataset(
            args.benign,
            args.output
        )
        
        logging.info("Analysis completed successfully!")
        logging.info(f"Results saved to:")
        logging.info(f"- CSV: {csv_path}")
        logging.info(f"- JSON: {json_path}")
        
    except Exception as e:
        logging.error(f"Error during processing: {str(e)}")
        raise

if __name__ == "__main__":
    main()