import sys
import json
import datetime
import uuid
import threading
import os
import hashlib
import hmac
import zmq
from zmq.eventloop import zmqstream, ioloop as zmqloop
import aheui
import aheui.aheui
import aheui.compile

DELIM = b'<IDS|MSG>'


class Kernel(object):
    def __init__(self, **config):
        self._engine_id = str(uuid.uuid4())
        self._execution_count = 0
        self._base_key = hmac.HMAC(
            config['key'].encode('ascii'),
            digestmod=hashlib.sha256
        )
        self._ip = config['ip']
        self._transport = config['transport']

        self._zmq = zmq.Context()
        zmqloop.install()

        self._hb_sock = self._make_zmq_conn(zmq.REP, config['hb_port'])

        self._shell_sock = self._make_zmq_conn(zmq.ROUTER, config['shell_port'])
        self._shell_io = zmqstream.ZMQStream(self._shell_sock)
        self._bind(self._shell_io, on_recv=self._on_shell)

        self._iopub_sock = self._make_zmq_conn(zmq.PUB, config['iopub_port'])
        self._iopub_io = zmqstream.ZMQStream(self._iopub_sock)

    def _make_zmq_conn(self, kind, port):
        url = '{transport}://{ip}:{port}'.format(
            transport=self._transport,
            ip=self._ip,
            port=port,
        )
        sock = self._zmq.socket(kind)
        sock.bind(url)
        return sock

    def _bind(self, stream, on_recv):
        stream.on_recv(on_recv)

    def _parse_data(self, data):
        print(data)

        sep = data.index(DELIM)
        ids = data[:sep]
        sig = data[sep+1]
        header        = json.loads(data[sep+2].decode('utf-8'))
        parent_header = json.loads(data[sep+3].decode('utf-8'))
        meta          = json.loads(data[sep+4].decode('utf-8'))
        content       = json.loads(data[sep+5].decode('utf-8'))

        return ids, header, parent_header, meta, content

    def _on_shell(self, data):
        identities, header, parent_header, meta, content = self._parse_data(data)

        if header['msg_type'] == 'kernel_info_request':
            content = {
                'protocol_version': '0.1',
                'language': 'aheui',
                'implementation': 'iaheui',
                'implementation_version': '0.1',
                'language_info': {
                    'name': 'aheui',
                    'version': '0.0',
                    'file_extension': '.aheui',
                },
                'banner': ''
            }

            self.send(self._shell_io, 'kernel_info_reply', content)

        elif header['msg_type'] == 'execute_request':
            self.send(self._iopub_io, 'status', {
                'execution_state': 'busy',
            }, parent_header=header)

            # self.send(stream, 'execute_input', {
            #     'execution_count': self._execution_count,
            #     'code': code,
            # }, parent_header=header)

            code = content['code']

            origin_stdout = os.dup(sys.stdout.fileno())

            out = open('tmp.out', 'w+')  # TODO : use temporary in memory
            os.dup2(out.fileno(), sys.stdout.fileno())

            compiler = aheui.compile.Compiler()
            compiler.compile(code)
            program = aheui.aheui.Program(compiler.lines, compiler.label_map)
            exitcode = aheui.aheui.mainloop(program, compiler.debug)

            out.flush()

            os.dup2(origin_stdout, sys.stdout.fileno())

            out.seek(0)
            result = out.read()
            out.close()

            # print('result : ' + result)

            self.send(self._iopub_io, 'stream', {
                'name': 'stdout',
                'text': result,
            }, parent_header=header)

            # self.send(stream, 'execute_result', {
            #     'execution_count': self._execution_count,
            #     'data': {
            #         'text/plain': 'result!'
            #     },
            #     'metadata': {}
            # }, parent_header=header)

            self.send(self._iopub_io, 'status', {
                'execution_state': 'idle',
            }, parent_header=header)

            metadata = {
                'dependencies_met': True,
                'engine': self._engine_id,
                'status': 'ok',
                'started': datetime.datetime.now().isoformat(),
            }
            content = {
                'status': 'ok',
                'execution_count': self._execution_count,
                'user_variables': {},
                'payload': [],
                'user_expressions': {},
            }
            self.send(self._shell_io, 'execute_reply', content, parent_header=header, identities=identities)

            self._execution_count += 1

    def sign(self, data):
        key = self._base_key.copy()
        for part in data:
            key.update(part)
        return key.hexdigest().encode('utf8')

    def send(self, stream, msg_type, content, identities=None, parent_header=None, meta=None):
        if not identities:
            identities = []

        if not parent_header:
            parent_header = {}

        if not meta:
            meta = {}

        header = {
            'version': '5.0',
            'msg_id': str(uuid.uuid4()),
            'date': datetime.datetime.now().isoformat(),
            'username': 'kernel',
            'session': self._engine_id,
            'msg_type': msg_type,
        }

        frames = [
            json.dumps(header).encode('utf-8'),
            json.dumps(parent_header).encode('utf-8'),
            json.dumps(meta).encode('utf-8'),
            json.dumps(content).encode('utf-8'),
        ]

        stream.send_multipart(identities + [DELIM, self.sign(frames)] + frames)
        stream.flush()

    def start_heartbeat(self):
        def heartbeat_loop():
            while True:
                zmq.device(zmq.FORWARDER, self._hb_sock, self._hb_sock)

        thread = threading.Thread(target=heartbeat_loop)
        thread.daemon = True
        thread.start()

        zmqloop.IOLoop.instance().start()


if __name__ == '__main__':
    ipy_config_path = sys.argv[1]
    config = json.load(open(ipy_config_path))

    kernel = Kernel(**config)
    kernel.start_heartbeat()
