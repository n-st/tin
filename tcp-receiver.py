#!/usr/bin/env python3

import argparse
import requests
import socket
import sys
import threading
import signal
import os
import pwd, grp
import logging
import logging.handlers
import hashlib
import base22


server_socket = None


def portnumber(value):
    try:
        ivalue = int(value)
    except ValueError:
         raise argparse.ArgumentTypeError("'%s' is not a valid port number (should be an integer between 1 and 65535)" % value)

    if not 1 <= ivalue <= 65535:
         raise argparse.ArgumentTypeError("'%s' is not a valid port number (should be an integer between 1 and 65535)" % value)

    return ivalue

def strlen_type(value):
    try:
        ivalue = int(value)
    except ValueError:
         raise argparse.ArgumentTypeError("'%s' is not a valid string length (should be an integer >= 1)" % value)

    if not 1 <= ivalue:
         raise argparse.ArgumentTypeError("'%s' is not a valid string length (should be an integer >= 1)" % value)

    return ivalue

def directory_type(value):
    if os.path.isdir(value):
        return value
    else:
         raise argparse.ArgumentTypeError("'%s' is not a valid directory path" % value)


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    """ Source: http://stackoverflow.com/a/2699996/1114687 """

    if os.getuid() != 0:
        # We're not root, so no need to drop privileges
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o077)

class PasteSubmissionException(Exception):
    def __init__(self, message, client_response):
        super(Exception, self).__init__(message)

        self.message = message
        self.client_response = client_response


def handle_connection(conn, addr, datapath, urlformat, strlen):
    try:
        data_buffer = []
        maxfilesize = 20000000

        while True:
            if len(data_buffer) > maxfilesize/4096:
                raise PasteSubmissionException('Maximum file size exceeded', 'error://maximum-filesize-exceeded')

            data = conn.recv(4096)

            if not data:
                break

            data_buffer.append(data)

        all_data = b''.join(data_buffer)
        del data_buffer

        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('%d bytes received' % len(all_data))

        hasher = hashlib.sha256()
        hasher.update(all_data)
        input_digest = hasher.digest()
        base22hash = base22.bytearray_to_base22(input_digest, strlen=strlen)

        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Computed hash: %s' % base22hash)

        filepath = os.path.join(datapath, base22hash)

        if os.path.exists(filepath):
            existing_size = os.path.getsize(filepath)
            input_size = len(all_data)

            if existing_size == input_size:
                hasher = hashlib.sha256()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        hasher.update(chunk)

                existing_digest = hasher.digest()

                is_same_file = (existing_digest == input_digest)

            else:
                is_same_file = False

            if is_same_file:
                logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('File \'%s\' already exists; content identical' % filepath)

                if urlformat:
                    url = urlformat % base22hash
                else:
                    url = 'http://%s/%s' % (conn.getsockname()[0], base22hash)

                conn.sendall(bytearray('%s\n' % url, "utf_8"))

            else:
                raise PasteSubmissionException('File \'%s\' already exists; content differs' % filepath, 'error://hash-collision--modify-a-byte-and-try-again')

        else:
            try:
                with open('data/%s' % base22hash, 'xb') as f:
                    f.write(all_data)

                logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('File stored')

                if urlformat:
                    url = urlformat % base22hash
                else:
                    url = 'http://%s/%s' % (conn.getsockname()[0], base22hash)

                conn.sendall(bytearray('%s\n' % url, "utf_8"))

            except Exception as e:
                raise PasteSubmissionException('Error while writing to file: \'%s\'' % str(e), 'error://could-not-write-file')

    except PasteSubmissionException as e:
        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).warn('%s' % e.message)
        conn.sendall(bytearray('%s\n' % e.client_response, "utf_8"))

    except Exception as e:
        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).error('Error: %s' % str(e))
        conn.sendall(bytearray('error://\n', "utf_8"))

    conn.close()
    logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Connection closed')


def start_server(port, host, datapath, urlformat, strlen):
    logging.getLogger('tin-tcp-recv').info('Starting TCP server on %s:%d...' % (host, port))

    global server_socket

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    try:
        server_socket.bind((host, port))

    except OSError as err:
        logging.getLogger('tin-tcp-recv').error('Bind failed: [Errno %d] %s' % (err.errno, err.strerror))
        sys.exit(err.errno)

    if os.getuid() == 0:
        logging.getLogger('tin-tcp-recv').info('Port bound, dropping privileges...')
        try:
            drop_privileges()

        except Exception as e:
            logging.getLogger('tin-tcp-recv').error('Error while trying to drop privileges: \'%s\'. Better safe than sorry, so let\'s stop right here.' % str(e))
            try:
                sys.exit(e.errno)
            except AttributeError:
                # The exception didn't have an errno
                sys.exit(-1)

    server_socket.listen(10)
    logging.getLogger('tin-tcp-recv').info('Now listening.')

    while True:
        # wait to accept a connection - blocking call
        conn, addr = server_socket.accept()
        logging.getLogger('[%s]:%d' % (addr[0], addr[1])).info('Connection accepted')

        threading.Thread(
                target=handle_connection,
                args=(conn, addr, datapath, urlformat, strlen),
            ).start()

    server_socket.close()
    server_socket = None


def exit_gracefully(signal_number, stack_frame):
    logging.getLogger('tin-tcp-recv').info('Received signal %d, preparing to exit.' % signal_number)

    global server_socket

    if server_socket is not None:
        logging.getLogger('tin-tcp-recv').info('Closing server socket.')
        server_socket.close()

    logging.getLogger('tin-tcp-recv').info('Terminating now.')

    sys.exit(0)


def configure_logging(to_syslog=False, verbose=False):
    class NoWarningOrHigherFilter(logging.Filter):
        def filter(self, record):
            return not record.levelno > logging.WARNING

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if to_syslog:
        log_formatter = logging.Formatter('%(levelname)s - %(name)s: %(message)s')

        syslog_logger = logging.handlers.SysLogHandler('/dev/log')
        syslog_logger.setFormatter(log_formatter)

        if verbose:
            syslog_logger.setLevel(logging.INFO)
        else:
            syslog_logger.setLevel(logging.WARNING)

        root_logger.addHandler(syslog_logger)

    else:
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s', '%b %e %H:%M:%S')

        stderr_logger = logging.StreamHandler(sys.stderr)
        stderr_logger.setLevel(logging.WARNING)
        stderr_logger.setFormatter(log_formatter)
        root_logger.addHandler(stderr_logger)

        if verbose:
            stdout_logger = logging.StreamHandler(sys.stdout)
            stdout_logger.setLevel(logging.INFO)
            stdout_logger.setFormatter(log_formatter)
            stdout_logger.addFilter(NoWarningOrHigherFilter())
            root_logger.addHandler(stdout_logger)


def main():
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    parser = argparse.ArgumentParser(description='Accepts data on a TCP port and forwards it to http://ix.io/')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--syslog', action='store_true', help='Send log messages to syslog instead of stdout/stderr')
    parser.add_argument('-p', '--port', type=portnumber, required=True)
    parser.add_argument('-l', '--strlen', type=strlen_type, default=6)
    parser.add_argument('--urlformat', type=str, help='Format string of what will be returned to uploading clients. %s will be replaced with the paste filename.')
    parser.add_argument('--datapath', type=directory_type, required=True, help='The directory where pastes will be stored')

    args = parser.parse_args()

    configure_logging(args.syslog, args.verbose)

    start_server(args.port, '', args.datapath, args.urlformat, args.strlen)

if __name__ == "__main__":
    main()
