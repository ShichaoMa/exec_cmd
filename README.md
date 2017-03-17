#多线程并发执行远程主机文件复制及远程命令执行

#INSTALL
##ubuntu
```bash
    git clone https://github.com/ShichaoMa/exec_cmd.git
    sudo python setup.py  install

    or

    sudo pip install executecmd
```
#START

```bash
    ubuntu@dev:~$ exec-cmd -h
    usage: execute_cmd.py [-h] {sftp,smc,ssh} ...

    ssh or sftp cmd execute.

    positional arguments:
      {sftp,smc,ssh}  Command.
        sftp          use sftp to send or receive files or floders to or from
                      remote.
        smc           simple cmd to execute.
        ssh           use ssh execute cmd in remote.

    optional arguments:
      -h, --help      show this help message and exit
    Command 'sftp'
    usage: execute_cmd.py sftp [-h] [-p] host_file

    Command 'smc'
    usage: execute_cmd.py smc [-h] --host HOST [--port PORT] -u USER -p PASSWORD
                              -c COMMAND

    Command 'ssh'
    usage: execute_cmd.py ssh [-h] [-f] [-b] host_file
```

#DESCRIPTION

--host_file 指定配置文件 格式参见：<br/>[host_file_ssh](https://github.com/ShichaoMa/exec_cmd/blob/master/host_file_ssh)<br/> [host_file_sftp](https://github.com/ShichaoMa/exec_cmd/blob/master/host_file_sftp)
##stfp 模式
-p 是否显示进度条<br/>
##ssh 模式
-f 每个远程主机指令集是否顺序执行，或并发执行<br/>
-b 是否阻塞进程等待指令集执行完毕，并返回信息<br/>
##smc 简单命令执行
--host host<br/>
--port port<br/>
-u username<br/>
-p password<br/>
-c command<br/>

