#!/usr/bin/env python3
import asyncio
import grp
import hashlib
import os
import pwd
import shlex
import shutil
import socket
import struct
import sys
import traceback
from inspect import cleandoc
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from asyncio.streams import StreamReader, StreamWriter
    from typing import List

services = ['kurisu', 'panopticon', 'panopticon-2', 'mod-mail', 'ninupdates-check']

# 'service name': 'username', 'repo in user directory'
service_info = {
    'kurisu': ('kurisu', 'Kurisu'),
    'panopticon': ('panopticon', 'panopticon'),
    'panopticon-2': ('panopticon', 'panopticon-2'),
    'mod-mail': ('mod-mail', 'discord-mod-mail'),
    'ninupdates-check': ('ninupdates-check', 'ninupdates-check'),
}


def p_wh(msg: str, dest: str = 'helpers'):
    requests.post(webhook_urls[dest], {'content': msg})


async def quick_run(*args, pd, stdin: bytes = None):
    k = {'stdout': asyncio.subprocess.PIPE, 'stderr': asyncio.subprocess.PIPE}
    if stdin:
        k = {'stdin': asyncio.subprocess.PIPE}

    proc = await asyncio.create_subprocess_exec(*args, **k)

    def dump_output(stdout, stderr):
        pd(f'Failed to run {args[0]}:')
        pd('--- stdout ---')
        pd(stdout.decode('utf-8'))
        pd('--- stderr ---')
        pd(stderr.decode('utf-8'))
        pd('--------------')

    if stdin:
        stdout, stderr = await proc.communicate(stdin)
        res = await proc.wait()
        if res:
            dump_output(stdout, stderr)
        return res
    else:
        res = await proc.wait()
        if res:
            dump_output(*(await proc.communicate()))
        return res


async def handle_conn(r: 'StreamReader', w: 'StreamWriter'):
    raw_socket: socket.socket = w.get_extra_info('socket')
    creds = raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    user = pwd.getpwuid(uid).pw_name

    def pd(*m, sep=' '):
        messages = sep.join(str(x) for x in m)
        for l in messages.splitlines():
            print(user, '-', pid, '-', l)

    if not user:
        # pd('Could not find user by port, disconnecting.')
        w.write(b'disconnect\r\n')
        await w.drain()
        return

    try:
        with open(os.path.join(conf_path, 'discord-id', user), 'r') as f:
            mention = '<@!' + f.readline().strip() + '>'
    except FileNotFoundError:
        if os.getuid() == 0:
            mention = 'someone who is using the superuser'
        else:
            mention = user + ' (discord-id file not found)'

    pd('New connection received from:', user)

    try:
        # quick send
        async def qs(msg: str):
            w.write(msg.replace('\n', '\r\n').encode('utf-8'))
            await w.drain()

        while True:
            await qs('waiting\n')

            command_raw = (await r.read(1024))
            if not command_raw.startswith(b'nhd:'):
                # ignore useless messages
                continue

            try:
                command_str = command_raw[4:].decode('utf-8')
            except UnicodeDecodeError:
                await qs('unicode-err\n')
                continue

            # noinspection PyBroadException
            try:
                command_line: 'List[str]' = shlex.split(command_str)
                if len(command_line) == 0:
                    await qs('empty-cmd\n')
                    continue

                pd('Received command:', command_line)
                cmd = command_line[0]
                args = command_line[1:]
                if cmd == 'exit':
                    break

                elif cmd == 'stop-daemon':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    loop.stop()
                    break

                elif cmd == 'ping':
                    await qs('pong\n')

                elif cmd == 'webhook-test':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    for k in webhook_urls.keys():
                        await qs('webhook-sending\n%s\n' % (k,))
                        p_wh(f'Webhook test from {mention}', dest=k)
                    await qs('webhook-test-done\n')

                elif cmd == 'list-units':
                    await qs('unit-list\n%s\n' % (' '.join(services),))

                elif cmd == 'update':
                    group = grp.getgrnam('nh-superop')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    if len(args) < 1:
                        await qs('missing-arg\n')
                        continue

                    unk = []
                    for s in args:
                        if s not in services:
                            unk.append(s)

                    if unk:
                        await qs('unknown-svc\n%s\n' % (' '.join(unk),))
                        continue

                    p_wh(f'{mention} is updating: ' + ', '.join(args))

                    for svc in args:
                        svc_info = service_info[svc]
                        # don't mind this ugliness
                        script = cleandoc(f"""
                        cd $HOME/{svc_info[1]}
                        git pull
                        """)
                        if await quick_run('sudo', '-H', '-u', svc_info[0], 'bash', pd=pd,
                                           stdin=script.encode('utf-8')):
                            await qs(f'update-err\n{svc}\n')
                            continue

                        if await quick_run('systemctl', 'restart', svc, pd=pd):
                            await qs(f'systemctl-err\n{svc}\n')
                            continue

                    await qs('updated\n')

                elif cmd == 'notify-reboot':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    if len(args) < 1:
                        await qs('missing-arg\n')
                        continue

                    try:
                        with open(os.path.join(conf_path, 'notify-reboot', args[0])) as f:
                            message = f.read().strip()
                    except FileNotFoundError:
                        await qs('unknown-code\n')
                        continue

                    p_wh(f'{message} (Initialized by {mention})')

                    await qs('rebooting\n')

                    # don't really need to do special asyncio stuff with this
                    os.system('systemctl reboot')

                    loop.stop()
                    break

                elif cmd == 'notify-session':
                    if user != 'root':
                        await qs('no-perm\n')
                        continue

                    if len(args) < 2:
                        await qs('missing-arg\n')
                        continue

                    l_username_given = args[0]
                    l_type = args[1]
                    l_publickey = args[2].strip()
                    l_publickey_hash = hashlib.sha256(l_publickey.encode('utf-8')).hexdigest()

                    try:
                        with open(os.path.join(conf_path, 'ssh-key-names', l_publickey_hash + '.publickey'),
                                  encoding='utf-8') as i:
                            l_username = i.readline().strip()
                    except FileNotFoundError:
                        p_wh(f'@everyone Unknown public key used to log into {l_username_given}\n'
                             f'```\n'
                             f'{l_publickey}\n'
                             f'```', 'staff')
                    else:

                        try:
                            with open(os.path.join(conf_path, 'discord-id', l_username), 'r') as i:
                                discord_mention = f'<@!{i.readline().strip()}>'
                        except FileNotFoundError:
                            discord_mention = 'No Discord ID attached, please fix'

                        if l_type == 'open_session':
                            message = f'Opened session for user {l_username_given} (public key {discord_mention})'
                        elif l_type == 'close_session':
                            message = f'Closed session for user {l_username_given}'
                        else:
                            message = f'Unhandled PAM_TYPE ({l_type}) for user {l_username_given} ' \
                                f'(public key {discord_mention}'

                        p_wh(message, 'staff')

                elif cmd == 'add-user':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    if len(args) < 4:
                        await qs('missing-arg\n')
                        continue

                    try:
                        new_username = args[0]
                        new_full_name = args[1]
                        new_discord_id = int(args[2])
                        new_ssh_keypath = args[3]
                    except ValueError:
                        await qs('syntax-err\n')
                        continue

                    try:
                        with open(new_ssh_keypath, 'rb') as f:
                            ssh_pub_key = f.readline(1024)
                            if not ssh_pub_key.startswith(b'ssh-rsa'):
                                await qs('invalid-ssh-key-format\n')
                                continue
                    except FileNotFoundError:
                        await qs('ssh-key-not-found\n')
                        continue

                    if await quick_run('adduser', new_username, '--disabled-password', '--gecos', new_full_name, pd=pd):
                        await qs('adduser-err\n')
                        continue

                    if await quick_run('adduser', new_username, 'nh-staff', pd=pd):
                        await qs('adduser-err\n')
                        continue

                    with open(os.path.join(conf_path, 'discord-id', new_username), 'w', encoding='utf-8') as o:
                        o.write(str(new_discord_id) + '\n')

                    publickey = b'publickey ' + b' '.join(ssh_pub_key.split()[0:2])
                    publickey_hash = hashlib.sha256(publickey).hexdigest()

                    with open(os.path.join(conf_path, 'ssh-key-names', publickey_hash + '.publickey'), 'w',
                              encoding='utf-8') as o:
                        o.write(new_username + '\n')

                    home_dir = pwd.getpwnam(new_username).pw_dir
                    os.chmod(home_dir, 0o751)

                    ssh_dir = os.path.join(home_dir, '.ssh')
                    ssh_auth_keys = os.path.join(ssh_dir, 'authorized_keys')
                    os.makedirs(ssh_dir, 0o700, exist_ok=True)

                    with open(ssh_auth_keys, 'wb') as o:
                        o.write(ssh_pub_key)

                    os.chmod(ssh_auth_keys, 0o600)
                    shutil.chown(ssh_dir, new_username, new_username)
                    shutil.chown(ssh_auth_keys, new_username, new_username)

                    p_wh(f'User added by {mention}:\n'
                         f'username: {new_username}\n'
                         f'fullname: {new_full_name}\n'
                         f'discord-id: {new_discord_id}', dest='staff')

                    await qs('user-added\n')

                elif cmd == 'del-user':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    try:
                        d_username = args[0]
                        d_delete_home = int(args[1])
                    except ValueError:
                        await qs('syntax-err\n')
                        continue

                    try:
                        os.unlink(os.path.join(conf_path, 'discord-id', d_username))
                    except FileNotFoundError:
                        # this should only be used for NH staff, not general system users
                        await qs('not-nh-user\n')
                        continue

                    args = []
                    if d_delete_home:
                        args.append('--remove-home')

                    if await quick_run('deluser', d_username, *args, pd=pd):
                        await qs('deluser-err\n')
                        continue

                    p_wh(f'User deleted by {mention}: {d_username} (home-dir deleted)', dest='staff')

                    await qs('user-deleted\n')

                elif cmd == 'disable-user':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    try:
                        d_username = args[0]
                    except ValueError:
                        await qs('syntax-err\n')
                        continue

                    if not os.path.isfile(os.path.join(conf_path, 'discord-id', d_username)):
                        await qs('not-nh-user\n')
                        continue

                    if await quick_run('usermod', '-L', '-e', '1', d_username, pd=pd):
                        await qs('usermod-err\n')
                        continue

                    p_wh(f'User disabled by {mention}: {d_username}', dest='staff')

                    await qs('user-disabled\n')

                elif cmd == 'enable-user':
                    group = grp.getgrnam('sudo')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    try:
                        d_username = args[0]
                    except ValueError:
                        await qs('syntax-err\n')
                        continue

                    if not os.path.isfile(os.path.join(conf_path, 'discord-id', d_username)):
                        await qs('not-nh-user\n')
                        continue

                    if await quick_run('usermod', '-U', '-e', '', d_username, pd=pd):
                        await qs('usermod-err\n')
                        continue

                    p_wh(f'User enabled by {mention}: {d_username}', dest='staff')

                    await qs('user-enabled\n')

                elif cmd in {'restart', 'restart-force'}:
                    group = grp.getgrnam('nh-superop')
                    if user not in group.gr_mem:
                        await qs('no-perm\n')
                        continue

                    if len(args) == 0:
                        await qs('missing-arg\n')
                        continue

                    unk = []
                    for s in args:
                        if s not in services:
                            unk.append(s)

                    if unk:
                        await qs('unknown-svc\n%s\n' % (' '.join(unk),))
                        continue

                    # normal restart
                    if cmd == 'restart':
                        p_wh(f'{mention} is restarting: ' + ', '.join(args))

                        if await quick_run('systemctl', 'restart', *args, pd=pd):
                            await qs('systemctl-err\n')
                            continue

                    # kill and restart
                    elif cmd == 'restart-force':
                        p_wh(f'{mention} is forcibly restarting: ' + ', '.join(args))

                        if await quick_run('systemctl', 'kill', '--signal=9', *args, pd=pd):
                            await qs('systemctl-err\n')
                            continue

                        if await quick_run('systemctl', 'start', *args, pd=pd):
                            await qs('systemctl-err\n')
                            continue

                    await qs('svc-restarted\n')

                else:
                    await qs('unknown-cmd\n%s\n' % (cmd,))

            except Exception:
                pd('Unexpected exception:')
                pd(traceback.format_exc())
                await qs('internal-error\n')
                break

        pd('Disconnecting.')
        await qs('disconnect\n')
        w.close()
    except ConnectionResetError:
        pd('Connection was lost.')

# expecting to be run by systemd
if os.getppid() != 1 and 'test' not in sys.argv or os.getuid() != 0:
    sys.exit('nhd cannot be run directly.')

default_conf_path = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..', 'etc', 'nhd'))
conf_path = os.environ.get('NHD_CONF_PATH', default_conf_path)
webhook_path = os.path.join(conf_path, 'webhook.conf')
webhook_urls = {}
with open(webhook_path, 'r') as f:
    for l in f:
        dest, url = l.split(':', 1)
        webhook_urls[dest] = url.strip()

if 'helpers' not in webhook_urls or 'staff' not in webhook_urls:
    print('webhook.conf is incomplete. Please add urls for helpers and staff.')

if os.stat(webhook_path).st_mode & 0o777 != 0o600:
    print('Fatal error: Not starting because', webhook_path, 'mode is not 0600.')
    sys.exit(1)

loop = asyncio.get_event_loop()
# server = loop.run_until_complete(asyncio.start_server(handle_conn, 'localhost', 18510, loop=loop))
socket_fn = '/run/nhd.socket' if 'test' not in sys.argv else '/run/nhd_test.socket'
server = loop.run_until_complete(asyncio.start_unix_server(handle_conn, socket_fn))
os.chmod(socket_fn, 0o666)

try:
    print('nhd started')
    loop.run_forever()
except KeyboardInterrupt:
    pass

server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
