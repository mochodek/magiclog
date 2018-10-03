import logging
from abc import ABC, abstractmethod
import re
import sys
import xml.dom.minidom as minidom
import paramiko
from pprint import pprint

HOUR_PATTERN = "((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)"

class BaseLogEntriesLoader(object):
    """An abstract class for loading a log file entries"""

    def __init__(self, contains, new_entry_patterns, lines):
        """
        Parameters
        ----------
        contains : list of str
            If an entry doesn't contain any of these strings, it is ignored.
        new_entry_patterns : list of strings.
            If a line matches any of the regexps, it is treated as a start of a new entry.
        lines : int
            The number of last lines to read and parse.
        """
        self.logger = logging.getLogger('magiclog.loaders.BaseLogEntriesLoader')
        self.contains = contains
        self.new_entry_patterns = new_entry_patterns
        self.lines = lines
        self.content = []
        self.entries = []

    @abstractmethod
    def _load_lines(self):
        pass

    def _is_entry_header(self, line):
        for pattern in self.new_entry_patterns:
            if re.search(pattern, line) is not None:
                return True
        return False

    def _is_valid(self, entry):
        if len(self.contains) == 0:
            return True

        entry_text = " ".join(entry)
        for looked_text in self.contains:
            if looked_text in entry_text:
                return True

        return False

    def _create_entry(self, entry_lines, line_no):
        entry = {}

        entry_text = "\n".join(entry_lines)
        entry['line'] = line_no
        entry['header'] = entry_lines[0]
        hours = re.findall(HOUR_PATTERN, entry['header'])
        if len(hours) > 0:
            entry['hour'] = hours[0]
        else:
            entry['hour'] = None
        xml_dirty = re.findall("<[?]xml.*>", entry_text, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        entry['xml'] = []
        for xml_text in xml_dirty:
            entry['xml'].append(re.sub(r'(\n)\1{1,}', r'\1', minidom.parseString(xml_text).toprettyxml()))

        return entry


    def load(self):
        self.content = self._load_lines()
        if len(self.content) > self.lines:
            self.content = self.content[-self.lines:]

        self.entries = []
        current_entry = []
        for i, line in enumerate(self.content):
            if self._is_entry_header(line):
                if len(current_entry) > 0:
                    if self._is_valid(current_entry):
                        self.entries.append(self._create_entry(current_entry, i+self.lines+1))
                    current_entry = []

            current_entry.append(line)


class LocalFileLogEntriesLoader(BaseLogEntriesLoader):
    """Loads log entries from a local file"""

    def __init__(self, logfile, contains, new_entry_patterns, lines):
        """
        Parameters
        ----------
        logfile : str
            A path to the log file.
        """
        super(LocalFileLogEntriesLoader, self).__init__(contains, new_entry_patterns, lines)
        self.logger = logging.getLogger('magiclog.loaders.LocalFileLogEntriesLoader')
        self.logfile = logfile

    def _load_lines(self):
        self.logger.debug("Loading {}".format(self.logfile))
        with open(self.logfile, 'r', encoding="utf-8", errors='replace') as f:
            return f.readlines()
        return []



class SSHFileLogEntriesLoader(BaseLogEntriesLoader):
    """Loads log entries from a local file"""

    def __init__(self, server, user, password, logfile, contains, new_entry_patterns, lines):
        """
        Parameters
        ----------
        logfile : str
            A path to the log file.
        """
        super(SSHFileLogEntriesLoader, self).__init__(contains, new_entry_patterns, lines)
        self.logger = logging.getLogger('magiclog.loaders.LocalFileLogEntriesLoader')
        self.logfile = logfile
        self.server = server
        self.user = user
        self.password = password

    def _load_lines(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=self.server, username=self.user, password=self.password)
        stdin, stdout, stderr = ssh_client.exec_command("cat {}".format(self.logfile))
        lines = stdout.readlines()
        ssh_client.close()
        return lines
