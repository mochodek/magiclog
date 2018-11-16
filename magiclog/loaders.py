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

    def _create_entry(self, entry_lines):
        entry = {}

        entry_text = "\n".join(entry_lines)
        entry['lines'] = entry_lines
        entry['header'] = entry_lines[0]
        hours = re.findall(HOUR_PATTERN, entry['header'])
        if len(hours) > 0:
            entry['hour'] = hours[0]
        else:
            entry['hour'] = None
        xml_dirty = re.findall("<.*>", entry_text, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        entry['xml'] = []
        for xml_text in xml_dirty:
            try:
                entry['xml'].append(re.sub(r'(\n)\1{1,}', r'\1', minidom.parseString(xml_text).toprettyxml()))
            except:
                entry['xml'].append(xml_text)

        return entry


    def load(self):
        self.content = self._load_lines()
        total_lines = len(self.content)
        if len(self.content) > self.lines:
            self.content = self.content[-self.lines:]

        self.entries = []
        current_entry = []
        for i, line in enumerate(self.content):
            if self._is_entry_header(line):
                if len(current_entry) > 0:
                    if self._is_valid(current_entry):
                        self.entries.append(self._create_entry(current_entry))
                    current_entry = []

            current_entry.append(line)


class LocalFileLogEntriesLoader(BaseLogEntriesLoader):
    """Loads log entries from a local file"""

    def __init__(self, logfile_path, contains, new_entry_patterns, lines):
        """
        Parameters
        ----------
        logfile_path : str
            A path to the log file.
        contains : list of str
            If an entry doesn't contain any of these strings, it is ignored.
        new_entry_patterns : list of strings.
            If a line matches any of the regexps, it is treated as a start of a new entry.
        lines : int
            The number of last lines to read and parse.
        """
        super(LocalFileLogEntriesLoader, self).__init__(contains, new_entry_patterns, lines)
        self.logger = logging.getLogger('magiclog.loaders.LocalFileLogEntriesLoader')
        self.logfile_path = logfile_path

    def _load_lines(self):
        self.logger.debug("Loading {}".format(self.logfile_path))
        with open(self.logfile_path, 'r', encoding="utf-8", errors='replace') as f:
            return f.readlines()
        return []

    def set_contains(self, contains):
        LocalFileLogEntriesLoader.contains = contains
        self.contains = contains

    def set_lines(self, lines):
        LocalFileLogEntriesLoader.lines = lines
        self.lines = lines



class SSHFileLogEntriesLoader(BaseLogEntriesLoader):
    """Loads log entries from a local file"""

    def __init__(self, host, user, password, logfile_path, contains, new_entry_patterns, lines):
        """
        Parameters
        ----------
        host : str
            Host address.
        user : str
            Username to login onto when using ssh.
        password : str
            User password for the ssh connection.
        logfile_path : str
            A path to the log file.
        contains : list of str
            If an entry doesn't contain any of these strings, it is ignored.
        new_entry_patterns : list of strings.
            If a line matches any of the regexps, it is treated as a start of a new entry.
        lines : int
            The number of last lines to read and parse.
        """
        super(SSHFileLogEntriesLoader, self).__init__(contains, new_entry_patterns, lines)
        self.logger = logging.getLogger('magiclog.loaders.SSHFileLogEntriesLoader')
        self.logfile_path = logfile_path
        self.host = host
        self.user = user
        self.password = password

    def _load_lines(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=self.host, username=self.user, password=self.password, compress=True)
        self.logger.info("Connecting to {}@{}...".format(self.user, self.host))
        stdin, stdout, stderr = ssh_client.exec_command("cat {} | tail -n {}".format(self.logfile_path, self.lines))
        self.logger.info("Reading lines...")
        lines = stdout.readlines()
        ssh_client.close()
        return lines

    def set_contains(self, contains):
        LocalFileLogEntriesLoader.contains = contains
        self.contains = contains

    def set_lines(self, lines):
        LocalFileLogEntriesLoader.lines = lines
        self.lines
