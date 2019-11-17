#!/usr/bin/env python3
import argparse
import os
import shlex
import socket
import sys
from subprocess import PIPE, run as sprun
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List


class NHDError(Exception):
    pass


class NHDRejectedError(NHDError):
    """Rejected connection."""


verbose = False
quiet = False

# copy from nhd
# maybe this should be stored in a separate file instead
services = ['kurisu', 'panopticon', 'panopticon-2', 'mod-mail', 'ninupdates-check']


def vp(*msg, source='nhctl', sep=' ', force=False):
    if verbose or force:
        final = sep.join(str(x) for x in msg)
        for line in final.splitlines():
            print(f'{source}:', line)


def ve(*msg, source='nhctl', sep=' '):
    if not quiet:
        final = sep.join(str(x) for x in msg)
        for line in final.splitlines():
            print(f'{source}: error:', line)


class NHDContext:
    conn: socket.socket
    closed = False

    def recv_lines(self, size=1024):
        vp('Waiting for response')
        res = self.conn.recv(size).decode('utf-8').splitlines()
        vp('Response:', res, source='nhd')
        return res

    def send(self, *message):
        final = ' '.join(shlex.quote(str(x)) for x in message)
        vp('Sending:', repr(final))
        self.conn.send(b'nhd:' + final.encode('utf-8') + b'\r\n')

    def __init__(self, test=False):
        vp('Creating socket')
        socket_fn = '/run/nhd.socket' if not test else '/run/nhd_test.socket'
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        vp('Connecting to nhd socket')
        try:
            self.conn.connect(socket_fn)
        except:
            self.closed = True
            raise
        res = self.recv_lines()
        if 'disconnect' in res:
            self.closed = True
            raise NHDRejectedError

    def __del__(self):
        if not self.closed:
            vp('Closing socket')
            self.send('exit')
            self.recv_lines()
            self.conn.close()
            self.closed = True

    close = __del__


# https://stackoverflow.com/questions/287871/print-in-terminal-with-colors
class b:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


UNLINKED = 0
DISABLED = 1
NOT_RUNNING = 2
FAILED = 3
RUNNING = 4
UNKNOWN = 5

status_messages = {
    UNLINKED: (b.FAIL, 'NOT-LINKED'),
    DISABLED: (b.WARNING, 'NOT-ENABLED'),
    NOT_RUNNING: (b.WARNING, 'NOT-STARTED'),
    FAILED: (b.FAIL, 'FAILED'),
    RUNNING: (b.OKGREEN, 'RUNNING')
    UNKNOWN: (b.FAIL, 'UNKNOWN')
}


def check_unit(name: str):
    # lazy way to check if it's linked
    if not os.path.isfile('/etc/systemd/system/' + name + '.service'):
        return UNLINKED

    is_enabled = sprun(['systemctl', 'is-enabled', name], stdout=PIPE, stderr=PIPE)
    if is_enabled.stdout.startswith(b'linked'):
        return DISABLED

    is_active = sprun(['systemctl', 'is-active', name], stdout=PIPE, stderr=PIPE)
    if is_active.stdout.startswith(b'inactive'):
        return NOT_RUNNING
    elif is_active.stdout.startswith(b'failed'):
        return FAILED
    elif is_active.stdout.startswith(b'active'):
        return RUNNING

    return UNKNOWN


def main(argv: 'List[str]' = None):
    global verbose, quiet
    parser = argparse.ArgumentParser(description='Control the Nintendo Homebrew daemon.')
    parser.add_argument('-v', '--verbose', help='print more information', action='store_true')
    parser.add_argument('-q', '--quiet', help='suppress error output', action='store_true')
    parser.add_argument('-t', '--test', help=argparse.SUPPRESS, action='store_true')
    subparser = parser.add_subparsers(help='Sub-commands', dest='command')

    p_restart = subparser.add_parser('restart', help='restart services')
    p_restart.add_argument('service', help='service to restart', nargs='+')
    p_restart.add_argument('-f', '--force', help='force a restart', action='store_true')

    p_update = subparser.add_parser('update', help='update services')
    p_update.add_argument('service', help='service to update', nargs='+')

    p_status = subparser.add_parser('status', help='show service status')
    p_status.add_argument('service', help='service to check status of', nargs='*')

    p_add_user = subparser.add_parser('add-user', help='add a staff user')
    p_add_user.add_argument('-u', '--username', help='username for the linux system', required=True)
    p_add_user.add_argument('-k', '--ssh-public-key', metavar='KEY_FILE', help='ssh public key file', required=True)
    p_add_user.add_argument('-d', '--discord-name', help='discord username, without discriminator', required=True)
    p_add_user.add_argument('-i', '--discord-id', help='discord user id', type=int, required=True)

    p_del_user = subparser.add_parser('del-user', help='remove a staff user')
    p_del_user.add_argument('-u', '--username', help='username to delete')
    p_del_user.add_argument('--remove-home', help='delete home', action='store_true')

    p_disable_user = subparser.add_parser('disable-user', help="disable a staff user")
    p_disable_user.add_argument('-u', '--username', help='username to disable')

    p_enable_user = subparser.add_parser('enable-user', help="enable a staff user")
    p_enable_user.add_argument('-u', '--username', help='username to enable')

    p_notify_reboot = subparser.add_parser('notify-reboot', help='reboot the system and notify the server')
    m_group = p_notify_reboot.add_mutually_exclusive_group(required=True)
    m_group.add_argument('-l', '--list', dest='list_messages', help='list messages', action='store_true')
    m_group.add_argument('-m', '--message', help='message to send')

    # subparsers without extra arguments
    subparser.add_parser('list-services', help='list available services')
    subparser.add_parser('ping', help='test connection')
    subparser.add_parser('webhook-test', help='test webhooks')

    # hidden commands
    hp_notify_login = subparser.add_parser('notify-session', help=argparse.SUPPRESS)
    hp_notify_login.add_argument('username', help='username in session')
    hp_notify_login.add_argument('type', help='type')
    hp_notify_login.add_argument('publickey', help='publickey in use')

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_usage()
        sys.exit()

    default_conf_path = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'etc', 'nhd'))
    conf_path = os.environ.get('NHD_CONF_PATH', default_conf_path)

    verbose = args.verbose
    quiet = args.quiet

    if args.command == 'list-services':
        print('\n'.join(services))
        return 0
    elif args.command == 'status':
        if args.service:
            for s in args.service:
                message = status_messages[check_unit(s)]
                print(message[1])
        else:
            for s in services:
                message = status_messages[check_unit(s)]
                print(s.ljust(17), message[0] + message[1] + b.ENDC)
        return 0
    elif args.command == 'notify-reboot' and args.list_messages:
        messages = []
        for e in os.scandir(os.path.join(conf_path, 'notify-reboot')):
            with open(e, encoding='utf-8') as i:
                messages.append((e.name, i.read().strip()))

        messages.sort(key=lambda x: x[0])
        for c, m in messages:
            print(c, m, sep='\t')

        return 0

    # commands that require more permissions
    try:
        ctx = NHDContext(test=args.test)
    except ConnectionRefusedError:
        ve('could not connect to nhd')
        return 1
    except NHDRejectedError:
        ve('nhd rejected connection')
        return 1

    exitcode = 0

    res: 'List[str]' = []

    if args.command == 'ping':
        ctx.send('ping')
        res = ctx.recv_lines()
        print('response:', res)

    if args.command == 'webhook-test':
        ctx.send('webhook-test')
        while True:
            res = ctx.recv_lines()
            if 'webhook-test-done' in res:
                break
            if 'webhook-sending' not in res and 'webhook-test-done' not in res:
                break
            vp('testing webhook for', res[1], source='nhd', force=True)

    if args.command == 'add-user':
        ctx.send('add-user', args.username, args.discord_name, args.discord_id,
                 os.path.abspath(args.ssh_public_key))
        res = ctx.recv_lines()
        if 'ssh-key-not-found' in res:
            ve(f'{args.ssh_public_key}: no such file or directory')
        if 'invalid-ssh-key-format' in res:
            ve('invalid SSH public key format, OpenSSH needed')
            exitcode = 1
        if 'adduser-err' in res:
            ve('internal adduser error', source='nhd')
            exitcode = 1

    elif args.command == 'del-user':
        ctx.send('del-user', args.username, int(args.remove_home))
        res = ctx.recv_lines()
        if 'not-nh-user' in res:
            ve('cannot be used with generic system users')
            exitcode = 1
        if 'deluser-err' in res:
            ve('internal deluser error', source='nhd')
            exitcode = 1

    elif args.command == 'disable-user':
        ctx.send('disable-user', args.username)
        res = ctx.recv_lines()
        if 'not-nh-user' in res:
            ve('cannot be used with generic system users')
            exitcode = 1
        if 'usermod-err' in res:
            ve('internal usermod error', source='nhd')
            exitcode = 1

    elif args.command == 'enable-user':
        ctx.send('enable-user', args.username)
        res = ctx.recv_lines()
        if 'not-nh-user' in res:
            ve('cannot be used with generic system users')
            exitcode = 1
        if 'usermod-err' in res:
            ve('internal usermod error', source='nhd')
            exitcode = 1

    elif args.command == 'restart':
        cmd = 'restart-force' if args.force else 'restart'
        ctx.send(cmd, *args.service)
        res = ctx.recv_lines()
        if 'unknown-svc' in res:
            unk_index = res.index('unknown-svc') + 1
            unk_services = res[unk_index].split()
            ve('unknown services', ', '.join(unk_services))
            exitcode = 1
        if 'systemctl-err' in res:
            ve('internal systemctl error', source='nhd')
            exitcode = 1

    elif args.command == 'notify-reboot':
        ctx.send('notify-reboot', args.message)
        res = ctx.recv_lines()
        if 'unknown-code' in res:
            ve('unknown message code')
            exitcode = 1

    elif args.command == 'update':
        ctx.send('update', *args.service)
        res = ctx.recv_lines()
        if 'unknown-svc' in res:
            unk_index = res.index('unknown-svc') + 1
            unk_services = res[unk_index].split()
            ve('unknown services', ', '.join(unk_services))
            exitcode = 1
        if 'systemctl-err' in res:
            ve('internal systemctl error', source='nhd')
            exitcode = 1
        if 'update-err' in res:
            ve('internal shell error', source='nhd')
            exitcode = 1

    elif args.command == 'notify-session':
        ctx.send('notify-session', args.username, args.type, args.publickey)
        res = ctx.recv_lines()

    if 'no-perm' in res:
        ve('permission denied')
        exitcode = 1
    if 'unknown-cmd' in res or 'syntax-err' in res or 'internal-error' in res or 'missing-arg' in res:
        ve('internal error', source='nhd')
        exitcode = 1

    ctx.close()
    return exitcode


if __name__ == '__main__':
    sys.exit(main())
