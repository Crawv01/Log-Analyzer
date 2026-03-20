"""
Base Parser

Defines the abstract interface all log parsers must implement.
Concrete parsers (LinuxAuthParser, WindowsEventParser) inherit from this class
to ensure a consistent API across log formats.
"""

from abc import ABC, abstractmethod
from typing import List, Iterator, Optional
from pathlib import Path

from src.models.events import AuthEvent


class BaseParser(ABC):
    """
    Abstract base class for authentication log parsers.

    Enforces a consistent interface across all supported log formats.
    Subclasses must implement parse_file, parse_line, parser_name,
    and get_supported_extensions.
    """

    @abstractmethod
    def parse_file(self, filepath: Path) -> List[AuthEvent]:
        """
        Parse an entire log file and return a list of normalized AuthEvents.

        Args:
            filepath: Path to the log file

        Returns:
            List of AuthEvent objects extracted from the file

        Raises:
            FileNotFoundError: If the file does not exist
            ParseError: If the file format is invalid or unreadable
        """
        pass

    @abstractmethod
    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """
        Parse a single log line into an AuthEvent.

        Args:
            line: A single line from the log file

        Returns:
            AuthEvent if the line represents a relevant authentication event,
            None if the line should be skipped (non-auth content, comments, etc.)
        """
        pass

    def parse_file_streaming(self, filepath: Path) -> Iterator[AuthEvent]:
        """
        Parse a log file in streaming fashion for memory-efficient processing.

        Useful for large log files that would be impractical to load entirely
        into memory. Yields events one at a time as each line is processed.

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
        Return the file extensions supported by this parser.

        Returns:
            List of extensions e.g. ['.log', ''] or ['.xml', '.evtx']
        """
        pass

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """
        Human-readable name for this parser.

        Returns:
            String identifying the parser e.g. "Linux Auth Log Parser"
        """
        pass


class ParseError(Exception):
    """
    Raised when a log file or line cannot be parsed.

    Attributes:
        message: Description of the parse failure
        line_number: Line number where the failure occurred (if applicable)
        raw_content: The content that could not be parsed (truncated to 100 chars)
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
