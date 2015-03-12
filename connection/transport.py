"""
Created on Nov 25, 2014

@author: Hideto Saito
"""
import logging
from abc import ABCMeta, abstractmethod


class Transport(object):
    """
    This class defines an abstract Transport methods
    Subclasses must implement below methods
    """

    __metaclass__ = ABCMeta

    def __init__(self, ip, username, password, timeout=600, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.transporter = None
        self.opened = False

    @abstractmethod
    def open(self):
        pass

    @abstractmethod
    def execute(self, command):
        pass

    @abstractmethod
    def close(self):
        pass
