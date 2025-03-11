import json
import numpy as np
import pickle
import torch
from torch.utils.data import Dataset, DataLoader, random_split
from torch.nn.utils.rnn import pad_sequence
import os

class JSONFeatureTokenizer:
    def __init__(self, encoder_path: str, threshold: int = 1):
        self.encoder = pickle.load(open(encoder_path, "rb"))
        self.name_mapping = self.create_name_mapping(threshold)
    
    def create_name_mapping(self, threshold: int):
        """Create a mapping from section names to 4-dimensional vectors."""
        mapping = {}
        for name, count in self.encoder.items():
            str_name = str(count)
            if count > threshold:
                continue
            n = len(str_name)
            # Ensure the string is at least 4 characters long
            str_name = "0" * (4 - n) + str_name if n < 4 else str_name[:4]
            mapping[name] = np.array([int(str_name[i]) for i in range(4)])
        return mapping

    def map_name_to_vector(self, name: str):
        """Convert section name to a 4-dimensional vector."""
        return self.name_mapping.get(name, np.zeros(4))

    def get_numeric_features(self, section: dict):
        """Extract numeric features from a section."""
        virtual_size = section.get("virtual_size", 0)
        virtual_address = section.get("virtual_address", 0)
        raw_size = section.get("raw_size", 0)
        entropy = section.get("entropy", 0)
        return np.array([virtual_size, virtual_address, raw_size, entropy], dtype=float)

    def tokenize(self, data: list):
        """Process JSON data and return a list of tensors (one per sample)."""
        tokenized_data = []
        for item in data:
            section_embeds = []
            if "pe_info" in item and "sections" in item["pe_info"]:
                for section in item["pe_info"]["sections"]:
                    if all(k in section for k in ["name", "virtual_size", "virtual_address", "raw_size", "entropy"]):
                        numeric_features = self.get_numeric_features(section)
                        name_vector = self.map_name_to_vector(section["name"])
                        embed = np.hstack([numeric_features, name_vector])  # Shape: (8,)
                        section_embeds.append(torch.tensor(embed, dtype=torch.float32))
            if section_embeds:
                tokenized_data.append(torch.stack(section_embeds))  # Shape: (num_sections, 8)
            else:
                tokenized_data.append(torch.empty((0, 8), dtype=torch.float32))  # Empty tensor for missing sections
        return tokenized_data
    
    def tokenize_sections(self,sections:list):
        tokenized_data=[]
        section_embeds = []
        if(len(sections)>0):
            for section in sections:        
                if all(k in section for k in ["name", "virtual_size", "virtual_address", "raw_size", "entropy"]):
                    numeric_features = self.get_numeric_features(section)
                    name_vector = self.map_name_to_vector(section["name"])
                    embed = np.hstack([numeric_features, name_vector])  # Shape: (8,)
                    section_embeds.append(torch.tensor(embed, dtype=torch.float32))
        if section_embeds:
                tokenized_data.append(torch.stack(section_embeds))
        else:
                tokenized_data.append(torch.empty((0, 8), dtype=torch.float32))  # Empty tensor for missing sections
        return tokenized_data
            