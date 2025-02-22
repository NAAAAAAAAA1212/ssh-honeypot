import os
import yaml
import logging
import socket
import threading
import base64
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import paramiko
from paramiko import RSAKey, ServerInterface, Transport
from rich.logging import RichHandler
from rich.traceback import install as install_rich_traceback
from logging.handlers import RotatingFileHandler

# 初始化Rich跟踪回溯
install_rich_traceback(show_locals=True)

# 加载配置
with open('settings.yml') as f:
    config = yaml.safe_load(f)

# 确保日志目录存在
log_dir = os.path.dirname(config['logging']['file'])
os.makedirs(log_dir, exist_ok=True)

# 配置日志系统
logger = logging.getLogger("SSH Honeypot")
logger.setLevel(logging.INFO)

# 文件日志处理器（带轮转）
file_handler = RotatingFileHandler(
    config['logging']['file'],
    maxBytes=config['logging']['max_size'],
    backupCount=config['logging']['backup_count']
)
file_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
file_handler.setFormatter(file_formatter)

# Rich控制台处理器
rich_handler = RichHandler(
    rich_tracebacks=True,
    tracebacks_show_locals=config['rich']['traceback_show_locals'],
    markup=True,
    show_time=config['rich']['show_time'],
    show_path=config['rich']['show_path']
)

logger.addHandler(file_handler)
logger.addHandler(rich_handler)

class EnhancedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.auth_credentials = (
            config['http']['username'],
            config['http']['password']
        )
        super().__init__(*args, **kwargs)

    def _check_auth(self):
        """HTTP基础认证验证"""
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Basic '):
            return False
        try:
            auth_decoded = base64.b64decode(auth_header[6:]).decode()
            username, password = auth_decoded.split(':', 1)
            return (username == self.auth_credentials[0] and 
                    password == self.auth_credentials[1])
        except:
            return False

    def _send_authenticate_header(self):
        """发送认证要求头"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Honeypot Monitor"')
        self.end_headers()

    def do_GET(self):
        """处理GET请求"""
        try:
            if not self._check_auth():
                self._send_authenticate_header()
                return

            if self.path == '/':
                self._handle_logs()
            else:
                self.send_error(404)
        except Exception as e:
            logger.error(f"HTTP处理错误: {str(e)}", exc_info=True)
            self.send_error(500, str(e))

    def _handle_logs(self):
        """处理日志显示"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()
        try:
            with open(config['logging']['file'], 'rb') as f:
                content = f.read()
                decoded_content = content.replace(b'\r\n', b'\n').decode('utf-8', 'ignore')
                lines = decoded_content.split('\n')[-config['http']['log_lines']:]
                response_content = '\n'.join(lines).encode('utf-8')
                self.wfile.write(response_content)
        except Exception as e:
            logger.error(f"读取日志文件失败: {str(e)}")
            self.send_error(500, "无法读取日志文件")

    def log_message(self, format, *args):
        """自定义日志格式"""
        try:
            status_code = int(args[1])
        except:
            status_code = -1
            logger.error("无法解析状态码")
        logger.info("[%s] %s \"%s\" %d",
                    self.log_date_time_string(),
                    self.client_address[0],
                    self.requestline,
                    status_code)

class HoneypotSSHServer(ServerInterface):
    def __init__(self, client_ip, transport):
        super().__init__()
        self.client_ip = client_ip
        self.transport = transport
        self.authenticated = False
        self.auth_attempts = []
        self.timer = None

    def check_auth_username(self, username):
        """用户名白名单验证"""
        if username not in config['ssh']['allowed_users']:
            logger.info(f"{self.client_ip} - 非法用户尝试: {username}")
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        """密码验证"""
        log_msg = f"{self.client_ip} - 认证尝试: {username}:{password}"
        logger.info(log_msg)
        self.auth_attempts.append(log_msg)
        
        if config['ssh']['enable_special_password']:
            if password == config['ssh']['allowed_password']:
                logger.warning(f"{self.client_ip} - 使用特殊密码登录成功!")
                self.authenticated = True
                self._schedule_disconnect()
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def _schedule_disconnect(self):
        if self.timer is None:
            self.timer = threading.Timer(0.1, self._force_disconnect)
            self.timer.start()

    def _force_disconnect(self):
        if self.transport.is_active():
            logger.info(f"{self.client_ip} - 主动断开已验证连接")
            self.transport.close()

    def check_channel_request(self, kind, chanid):
        if self.authenticated:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        return paramiko.OPEN_SUCCEEDED

def start_http_server():
    try:
        if config['http']['enable']:
            handler = partial(HoneypotHTTPHandler)
            httpd = EnhancedHTTPServer(('0.0.0.0', config['http']['port']), handler)
            logger.info(f"HTTP管理界面启动于端口 {config['http']['port']}")
            httpd.serve_forever()
    except Exception as e:
        logger.critical(f"HTTP服务器启动失败: {str(e)}", exc_info=True)
        raise

def handle_ssh_connection(client_sock, client_ip):
    transport = None
    timer = None
    try:
        transport = Transport(client_sock)
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
        host_key = RSAKey(filename=config['ssh']['host_key'])
        transport.add_server_key(host_key)
        
        server = HoneypotSSHServer(client_ip, transport)
        transport.start_server(server=server)

        timer = threading.Timer(
            config['ssh']['keep_alive'],
            lambda: transport.close() if transport.is_active() else None
        )
        timer.start()

        while transport.is_active():
            chan = transport.accept(0.5)
            if chan is not None and not server.authenticated:
                chan.close()

    except (socket.error, paramiko.SSHException) as e:
        logger.debug(f"客户端 {client_ip} 非正常断开: {str(e)}")
    except Exception as e:
        logger.error(f"处理错误 ({client_ip}): {str(e)}", exc_info=True)
    finally:
        try:
            if timer and timer.is_alive():
                timer.cancel()
            if transport and transport.is_active():
                transport.close()
            client_sock.close()
        except:
            pass

def main():
    try:
        if not os.path.exists(config['ssh']['host_key']):
            logger.info("生成新的RSA主机密钥...")
            RSAKey.generate(2048).write_private_key_file(config['ssh']['host_key'])

        if config['http']['enable']:
            http_thread = threading.Thread(target=start_http_server, daemon=True)
            http_thread.start()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', config['ssh']['port']))
        sock.listen(100)

        logger.info(f"SSH蜜罐启动成功，监听端口 {config['ssh']['port']}")
        logger.info(f"特殊通行密码: {config['ssh']['allowed_password']}")

        while True:
            client, addr = sock.accept()
            client_ip = addr[0]
            logger.info(f"新连接来自 {client_ip}")
            threading.Thread(
                target=handle_ssh_connection,
                args=(client, client_ip),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        logger.info("正在关闭服务...")
    except Exception as e:
        logger.critical(f"致命错误: {str(e)}", exc_info=True)
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    main()