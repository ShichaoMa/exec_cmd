# -*- coding:utf-8 -*-
import os
import sys
import time
import paramiko
import traceback
from threading import Thread, RLock, current_thread
from argparse import ArgumentParser, _HelpAction, _SubParsersAction

from multi_thread_closing import MultiThreadClosing

if sys.version_info >= (3, 0, 0):
    from io import StringIO
    from queue import Queue, Empty
else:
    from StringIO import StringIO
    from Queue import Queue, Empty


class ArgparseHelper(_HelpAction):
    """
        显示格式友好的帮助信息
    """

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, _SubParsersAction)]
        for subparsers_action in subparsers_actions:
            for choice, subparser in subparsers_action.choices.items():
                print("Command '{}'".format(choice))
                print(subparser.format_usage())

        parser.exit()


class CmdExecution(MultiThreadClosing):

    name = "cmd_execution"

    def __init__(self, host_file=None, cmd=None, follow=False, block=True,
                 process_bar=False, host=None, port=None, password=None,
                 user=None, command=None):
        super(CmdExecution, self).__init__()
        self.host = host
        self.port = port
        self.pwd = password
        self.user = user
        self.command = command
        self.host_file = host_file
        self.cmd = cmd
        self.follow = follow
        self.process_bar = process_bar
        self.block = block
        self.results = 0
        self.msg_queue = Queue()
        self.lock = RLock()
        self.hosts_cmds = {}
        self._threads = {}
        self.sftp_list = []
        self.setup()

    def parse_settings(self, buf=None):
        """
        解析hosts_file文件
        :param buf: 可以是buf的形式传入
        :return:
        """
        if buf:
            fobj = StringIO(buf)
        else:
            fobj = open(self.host_file)
        for line in fobj.readlines():
            line = line.strip("\357\273\277\r\n")
            if line.startswith("#") or not line:
                continue
            getattr(self, "parser_%s" % self.cmd)(line)

    def parser_sftp(self, line):
        self.sftp_list.append(tuple(line.split("      ")))

    def parser_ssh(self, line):
        host, cmds = line.split("      ")
        cmds = [(x.strip(), False) for x in cmds.split("    ")]
        self.hosts_cmds[host] = cmds

    def setup(self, settings=None):
        """
        添加ssh 或 scp 线程
        :param settings:
        :return:
        """
        if self.cmd == "smc":
            return
        self.parse_settings(settings)
        if self.cmd == "ssh":
            for host in self.hosts_cmds.keys():
                self._threads[host] = Thread(target=self.thread_process, args=(host, ))
                self.threads.append(self._threads[host])
        else:
            for pair in enumerate(self.sftp_list):
                self._threads[pair] = Thread(target=self.thread_process, args=(pair, ))
                self.threads.append(self._threads[pair])

    def thread_process(self, arg):
        getattr(self, "process_%s"%self.cmd)(arg)

    def incr_result_count(self, host):
        self.lock.acquire()
        if self.follow or self.cmd == "sftp":
            self.results += 1
        else:
            self.results += len(self.hosts_cmds[host])
        self.lock.release()

    def process_ssh(self, host):
        self.incr_result_count(host)
        if self.follow:
            self.cmd_one_by_one(host)
        else:
            self.concurrent(host)

    def process_sftp(self, pair):
        self.incr_result_count(pair)
        index, pair = pair
        src_sftp, src, src_host = self.get_sftp(pair[0])
        dest_sftp, dest, dest_host = self.get_sftp(pair[1])
        src = src.strip()
        filename = src[src.rfind("/")+1:]
        temp_fn = ""
        try:
            if dest.endswith("/"):
                dest = "%s%s" % (dest, filename)
            if src_sftp:
                temp_fn = "temp/%s"%(src[src.rfind("/") + 1:] + current_thread().getName())
                if not os.path.exists("temp"):
                    os.mkdir("temp")
                src_sftp.get(src, temp_fn)
                dest_sftp.put(temp_fn, dest, callback=self.sftp_put_cb(src_host, dest_host))
            else:
                dest_sftp.put(src, dest, callback=self.sftp_put_cb(src_host, dest_host))
            self.msg_queue.put(index)
        except Exception:
            self.logger.error(traceback.format_exc())
        finally:
            if src_sftp:src_sftp.close()
            dest_sftp.close()
            if os.path.exists(temp_fn):
                os.remove(temp_fn)

    def sftp_put_cb(self, src, dest):
        """
        进度条回调函数
        :param src:
        :param dest:
        :return:
        """
        def callback(size, file_size):
            percent = int(size*100/file_size)
            if self.process_bar:
                self.logger.info("\r%s to %s %%%s |%s|. "%(src, dest, percent, '\033[47m \033[0m'*(percent/4)))
                if size == file_size:
                    self.logger.info("\nfinished!")
                return percent
        return callback

    def cmd_one_by_one(self, hosts):
        """
        顺序执行命令
        :param hosts:
        :return:
        """
        ssh = None
        try:
            cmds = [x[0] for x in self.hosts_cmds[hosts]]
            host, port, user, password = hosts.split("|")
            ssh = self.get_ssh(host, port, user, password)
            cmd = ("%s &&"*len(cmds))[:-2]%tuple(cmds)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            if not self.block:
                out, err = stdout.readlines(), stderr.readlines()
            else:
                out, err = "", ""
            self.msg_queue.put((hosts, cmds, out, err))
        except Exception:
            self.logger.error(traceback.format_exc())
        finally:
            if ssh:ssh.close()

    def get_sftp(self, src):
        host = "local"
        try:
            if src.count("|") == 4:
                host, port, user, password, path = [x.strip() for x in src.split("|")]
                t = paramiko.Transport((host, int(port)))
                t.connect(username=user, password=password)
                sftp = paramiko.SFTPClient.from_transport(t)
            else:
                path = src.strip()
                sftp = None
            return sftp, path, host
        except paramiko.AuthenticationException:
            self.logger.error("Authentication failed")
            self.logger.error("host:%s, port:%s, user:%s, password:%s" % (host, port, user, password))
            exit(1)
        except Exception:
            self.logger.error("error heppened in %s Error:%s"%(host, traceback.format_exc()))

    def get_ssh(self, host, port, user, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, int(port), user, password)
            return ssh
        except paramiko.AuthenticationException:
            self.logger.error("Authentication failed")
            self.logger.error("host:%s, port:%s, user:%s, password:%s"%(host, port, user, password))
            exit(1)
        except Exception:
            self.logger.error("error heppened in %s Error:%s"%(host, traceback.format_exc()))

    def concurrent(self, host):
        """
        并发执行指令
        :param host:
        :return:
        """
        cmds = [x[0] for x in self.hosts_cmds[host]]
        sub_queue = Queue()
        thread_list = []
        for cmd in cmds:
            thread_list.append(Thread(target=self.sub_thread_process, args=(host, cmd, sub_queue)))
        for thread in thread_list:
            self.threads.append(thread)
            thread.start()
        while sub_queue.qsize() < len(cmds) and [x for x in thread_list if x.is_alive()]:
            time.sleep(1)
        while True:
            try:
                self.msg_queue.put(sub_queue.get_nowait())
            except Empty:
                break

    def sub_thread_process(self, hosts, cmd, sub_queue):
        ssh = None
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            host, port, user, password = hosts.split("|")
            ssh.connect(host, int(port), user, password)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            if not self.block:
                out, err = stdout.readlines(), stderr.readlines()
            else:
                out, err = "", ""
            sub_queue.put((hosts, cmd, out, err))
        except Exception:
            self.logger.error("error heppened in %s Error:%s"%(hosts, traceback.format_exc()))
        finally:
            if ssh:
                ssh.close()

    def format_hosts_cmds(self):
        for host, cmds in self.hosts_cmds.items():
            host, port, user, port = host.split("|")
            host = "%s@%s"%(user, host)
            for cmd, result in cmds:
                if not result:
                    self.logger.error("Failed!")
                    self.logger.error("host:%s"%host)
                    self.logger.error("cmd:%s"%cmd)
        for item in self.sftp_list:
            if item:
                self.logger.error("failed! sftp from %s to %s" % item)

    def process_result(self, item):
        """
        处理结果
        :param item:
        :return:
        """
        getattr(self, "%s_result"%self.cmd)(item)

    def sftp_result(self, item):
        sucess_item = self.sftp_list[item]
        self.logger.info("success! sftp from %s to %s"%sucess_item)
        self.sftp_list[item] = False

    def ssh_result(self, item):
        host, cmd, out, err = item
        if isinstance(cmd, list):
            for c in cmd:
                cmds = self.hosts_cmds[host]
                self.hosts_cmds[host] = [(c, True) if x[0] == c else x for x in cmds]
        else:
            cmds = self.hosts_cmds[                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    host]
            self.hosts_cmds[host] = [(cmd, True) if x[0] == cmd else x for x in cmds]
        host, port, user, password = host.split("|")
        host = "%s@%s" % (user, host)
        if out or err:
            self.logger.info("host:%s" % host)
            self.logger.info("cmd:%s" % cmd)
        if out:
            for o in out:
                self.logger.info(o.strip("\n"))
        if err:
            for e in err:
                self.logger.error(e.strip("\n"))

    def start(self):
        if self.cmd =="smc":
            ssh = None
            try:
                ssh = self.get_ssh(self.host, self.port, self.user, self.pwd)
                stdin, stdout, stderr = ssh.exec_command(self.command)
                for line in stdout.readlines() + stderr.readlines():
                    self.logger.info(line.strip())
            finally:
                if ssh: ssh.close()
        else:
            for i in self._threads.values():
                i.start()
            time.sleep(.1)
            while self.msg_queue.qsize() < self.results and [x for x in self._threads.values() if x.is_alive()]:
                time.sleep(1)
                while True:
                    try:
                        item = self.msg_queue.get_nowait()
                        self.process_result(item)
                    except Empty:
                        break
            self.format_hosts_cmds()
            return self.hosts_cmds or self.sftp_list

    @classmethod
    def parse_args(cls):
        """
         ssh or sftp cmd execute.
        """
        parser = ArgumentParser(description=CmdExecution.parse_args.__doc__, add_help=False)
        parser.add_argument('-h', '--help', action=ArgparseHelper, help='show this help message and exit')
        base_parser = ArgumentParser(add_help=False)
        sub_parsers = parser.add_subparsers(help="Command. ", dest="cmd")
        base_parser.add_argument("host_file", help="settings of hosts")
        sftp_parser = sub_parsers.add_parser("sftp", parents=[base_parser],
                                             help="use sftp to send or receive files or floders to or from remote. ")
        sftp_parser.add_argument("-p", "--process-bar", action="store_true",
                                 dest="process_bar", help="show process bar")
        smc_parser = sub_parsers.add_parser("smc", help="simple cmd to execute. ")
        smc_parser.add_argument("--host", dest="host", help="host", required=True)
        smc_parser.add_argument("--port", dest="port", help="port", type=int, default=22)
        smc_parser.add_argument("-u", "--user", dest="user", help="user", required=True)
        smc_parser.add_argument("-p", "--pwd", dest="password", help="password", required=True)
        smc_parser.add_argument("-c", "--command", dest="command", help="command", required=True)
        ssh_parser = sub_parsers.add_parser("ssh", parents=[base_parser],
                                            help="use ssh execute cmd in remote. ")
        ssh_parser.add_argument("-f", "--follow", dest="follow", action="store_true",
                                help="execute cmd one by one in one host whether or not")
        ssh_parser.add_argument("-b", "--block", dest="block", action="store_true",
                                help="block cmd stdout and stderr whether or not")
        return cls(**vars(parser.parse_args()))


def main():
    CE = CmdExecution.parse_args()
    CE.set_logger()
    CE.start()


if __name__ == "__main__":
    main()

