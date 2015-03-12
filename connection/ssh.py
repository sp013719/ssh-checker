"""
Ssh Transport Module
"""

import paramiko
import logging
import socket
from paramiko.ssh_exception import *
from connection.transport import Transport

logging.basicConfig(level=logging.INFO)

SSH_TIMEOUT = 10        # FIXME: move me to config file
SSH_PORT = 22


class Ssh(Transport):
    """
    Ssh transport module is a simple wrapper of paramiko. A typical use case is::

        ssh = Ssh("10.10.1.1", "username", "password")
        ssh.open()
        if ssh.opened:
            result = ssh.execute("ipconfig")
            ssh.close()
        else:
            print "Error occurs during ssh connection establishment."

    It will only return None or False when error occurs during runtime.
    """

    def __str__(self):
        return "Ssh"

    def __init__(self, ip, username, password, timeout=SSH_TIMEOUT, port=SSH_PORT,
                 key_filename=None, logger=None):
        """
        Create a new Ssh object
        """
        super(Ssh, self).__init__(ip, username, password, timeout, port)
        self.key_filename = key_filename
        self.logger = logger or logging.getLogger(__name__)

    def _logging(self, ip, custom_message, message="", command="", exit_status=-1, error=False):
        """
        Format internal logging
        :param ip: target IP
        :param custom_message: message we want to tell user
        :param message: exception.message
        :param command: desired command we execute
        :param exit_status: ssh exit status
        :param error: logging level
        """
        log = "[%s] IP: %s, MSG: %s - %s, CMD: %s, EXIT_STATUS: %s" % \
              (self, ip, custom_message, message, command, str(exit_status))
        self.logger.error(log) if error else self.logger.debug(log)

    def _authenticate(self):
        """
        Wrapper for ssh connection establishment
        """
        try:
            if self.key_filename:
                self.transporter.connect(self.ip, key_filename=self.key_filename,
                                         timeout=self.timeout, port=self.port)
            else:
                self.transporter.connect(self.ip, username=self.username, password=self.password,
                                         timeout=self.timeout, port=self.port, look_for_keys=False,
                                         allow_agent=False)
            self.opened = True
        except AuthenticationException as e:
            self._logging(self.ip, "Error credential", e.message, error=True)
        except socket.error as e:
            self._logging(self.ip, "Socket error occurred while connecting", e.message, error=True)
        except Exception as e:
            self._logging(self.ip, "Exception happened during ssh establishment",
                          e.message, error=True)

    def open(self):
        """
        Open a session to connect to remote server
        """
        self.transporter = paramiko.SSHClient()
        self.transporter.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._authenticate()
        self._logging(self.ip, "Connect to an SSH server and authenticate")
        return self.opened

    def _exec_command(self, command):
        self.transporter.get_transport().set_keepalive(1)
        return self.transporter.exec_command(command)

    def _stream_to_string(self, stream):
        #TODO - if it will be split at the end... please remove join for better performance
        return str(''.join(stream.readlines())).strip()

    def execute(self, command):
        """
        Execute a command
        :param command: user-specifed command which is desired running on remote machine
        :return: a string for the stdout; None if error occurs.
        """
        output = None
        exit_status = -1
        try:
            stdin, stdout, stderr = self._exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            stdin.close()
            output = self._stream_to_string(stdout)
            # logging when stdout doesn't contain anything
            if not len(output):
                message = "Stdout doesn't contain anything. stderr: %s" % self._stream_to_string(stderr)
                self._logging(self.ip, message, command=command, exit_status=exit_status)
        except SSHException as e:
            self._logging(self.ip, "Server fails to execute the command", e.message,
                          command=command, exit_status=exit_status, error=True)
        except Exception as e:
            self._logging(self.ip, "Exception happened during command execution",
                          e.message, command=command, exit_status=exit_status, error=True)

        return output

    def close(self):
        """
        Close a session
        """
        self.transporter.close()
        self.opened = False
        self._logging(self.ip, "Close the SSHClient successfully")
