"""
Input Handler Module

This module handles reading input.txt files, processing key-value pairs,
and validating input format.
"""
import re
import os
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

class InputHandlerError(Exception):
    @classmethod
    def file_not_found(cls, file_path: str) -> 'InputHandlerError':
        return cls(f"Input file not found: {file_path}")
    @classmethod
    def io_error(cls, file_path: str, error: str) -> 'InputHandlerError':
        return cls(f"Error reading file {file_path}: {error}")
    @classmethod
    def missing_separator(cls, line_number: int, line: str) -> 'InputHandlerError':
        return cls(
            f"Line {line_number}: Missing '=' separator. "
            f"Expected format: KEY = VALUE. Got: '{line}'"
        )
    @classmethod
    def invalid_format(cls, line_number: int, line: str) -> 'InputHandlerError':
        return cls(
            f"Line {line_number}: Invalid format. "
            f"Expected format: KEY = VALUE. Got: '{line}'"
        )

    @classmethod
    def unclosed_quote(cls, line_number: int, value: str) -> 'InputHandlerError':
        return cls(f"Line {line_number}: Unclosed quote in value. Got: '{value}'")
    
    @classmethod
    def duplicate_key(cls, line_number: int, key: str, prev_value: str, new_value: str) -> 'InputHandlerError':
        return cls(
            f"Line {line_number}: Duplicate key '{key}' found. "
            f"Previous value: '{prev_value}', New value: '{new_value}'"
        )
    @classmethod
    def missing_keys(cls, missing_keys: List[str]) -> 'InputHandlerError':
        return cls(f"Missing required keys: {', '.join(missing_keys)}")

class InputHandler:
    """
    A class to handle input file reading, key-value pair processing,
    and input format validation.
    """
    
    def __init__(self, file_path: str):
        
        self.file_path = Path(file_path)
        self.data: Dict[str, str] = {}
        self.raw_lines: List[str] = []
        
    def read_file(self) -> List[str]:
        try:
            if not self.file_path.exists():
                raise InputHandlerError.file_not_found(str(self.file_path))
            
            with open(self.file_path, 'r', encoding='utf-8') as file:
                self.raw_lines = [line.rstrip('\n\r') for line in file.readlines()]
            
            return self.raw_lines
            
        except (IOError, OSError) as e:
            raise InputHandlerError.io_error(str(self.file_path), str(e))
    
    def validate_line_format(self, line: str, line_number: int) -> bool:
        # Skip empty lines and comments
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#'):
            return True
        
        # Check for key = value format
        if '=' not in line:
            raise InputHandlerError.missing_separator(line_number, line)
        
        # Split only on the first '=' to handle values containing '='
        parts = line.split('=', 1)
        if len(parts) != 2:
            raise InputHandlerError.invalid_format(line_number, line)
        
        key, value = parts[0].strip(), parts[1].strip()
        
        # Check if value is properly quoted or unquoted
        if (value.startswith('"') and not value.endswith('"')) or \
           (value.startswith("'") and not value.endswith("'")):
            raise InputHandlerError.unclosed_quote(line_number, value)
        
        return True
    
    def parse_key_value_pair(self, line: str) -> Optional[Tuple[str, str]]:
        """
        Parse a line into a key-value pair.
        """
        stripped_line = line.strip()
        
        # Skip empty lines and comments
        if not stripped_line or stripped_line.startswith('#'):
            return None
        
        # Split on first '=' only
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        
        # Remove quotes if present
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        
        return key, value
    
    def process_file(self) -> Dict[str, str]:
        """
        Process the entire input file, validating format and extracting key-value pairs.
        """
        lines = self.read_file()
        self.data.clear()
        
        for line_number, line in enumerate(lines, 1):
            # Validate line format
            self.validate_line_format(line, line_number)
            
            # Parse key-value pair
            pair = self.parse_key_value_pair(line)
            if pair:
                key, value = pair
                
                # Check for duplicate keys
                if key in self.data:
                    raise InputHandlerError.duplicate_key(
                        line_number, key, self.data[key], value
                    )
                
                self.data[key] = value
        
        return self.data
    
    def get_value(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.data.get(key, default)
    
    def get_all_data(self) -> Dict[str, str]:
        self.data = self.process_file()
        return self.data.copy()
    
    def validate_required_keys(self, required_keys: List[str]) -> None:
        missing_keys = [key for key in required_keys if key not in self.data]
        if missing_keys:
            raise InputHandlerError.missing_keys(missing_keys)
    
    def __contains__(self, key: str) -> bool:
        """Check if a key exists in the data."""
        return key in self.data
    
    def __getitem__(self, key: str) -> str:
        """Get a value by key (dictionary-like access)."""
        return self.data[key]

    def json_dump(self)->json:
        self.data = self.process_file()
        json_str= json.dumps(self.data,indent=4)
        return json_str
    
# Convenience functions
def load_input_file(file_path: str = "input.txt") -> Dict[str, str]:

    handler = InputHandler(file_path)
    return handler.process_file()

if __name__ == "__main__":
    input = InputHandler("input.txt")
    data = input.process_file()
    
    print(input.json_dump())



