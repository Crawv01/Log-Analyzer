"""
Base Parser Abstract Class

This module defines the interface that all log parsers must implement.
You don't need to modify this file - just use it as a reference for
implementing your concrete parsers.
"""

from abc import ABC, abstractmethod
from typing import List, Iterator, Optional
from pathlib import Path

# Once you implement events.py, uncomment this:
# from src.models.events import AuthEvent


class BaseParser(ABC):
    """
    Abstract base class for log parsers.
    
    All parsers (Linux, Windows, etc.) should inherit from this class
    and implement the required methods.
    
    This ensures a consistent interface across all parser implementations.
    """
    
    @abstractmethod
    def parse_file(self, filepath: Path) -> List['AuthEvent']:
        """
        Parse an entire log file and return a list of AuthEvents.
        
        Args:
            filepath: Path to the log file
            
        Returns:
            List of normalized AuthEvent objects
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ParseError: If the file format is invalid
        """
        pass
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional['AuthEvent']:
        """
        Parse a single log line into an AuthEvent.
        
        Args:
            line: A single line from the log file
            
        Returns:
            AuthEvent if the line is a relevant authentication event,
            None if the line should be skipped (not auth-related)
        """
        pass
    
    def parse_file_streaming(self, filepath: Path) -> Iterator['AuthEvent']:
        """
        Parse a log file in streaming fashion (memory efficient).
        
        This is useful for very large log files that don't fit in memory.
        Default implementation reads line by line.
        
        Args:
            filepath: Path to the log file
            
        Yields:
            AuthEvent objects one at a time
        """
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                event = self.parse_line(line.strip())
                if event is not None:
                    yield event
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Return list of file extensions this parser supports.
        
        Returns:
            List of extensions like ['.log', '.txt'] or ['.xml', '.evtx']
        """
        pass
    
    @property
    @abstractmethod
    def parser_name(self) -> str:
        """
        Return a human-readable name for this parser.
        
        Returns:
            String like "Linux Auth Log Parser" or "Windows Security Event Parser"
        """
        pass


class ParseError(Exception):
    """
    Exception raised when parsing fails.
    
    Attributes:
        line_number: The line number where parsing failed (if applicable)
        raw_content: The content that couldn't be parsed
        message: Description of what went wrong
    """
    
    def __init__(self, message: str, line_number: int = None, raw_content: str = None):
        self.message = message
        self.line_number = line_number
        self.raw_content = raw_content
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        msg = self.message
        if self.line_number:
            msg += f" (line {self.line_number})"
        if self.raw_content:
            msg += f": {self.raw_content[:100]}"
        return msg
