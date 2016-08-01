# 多线程并发执行远程主机文件复制及远程命令执行<br/>
├── execute_cmd.py<br/>
├── host_file_scp<br/>
├── host_file_ssh<br/>
├── multi_thread_closing.py<br/>
└── README.md<br/>

ubuntu

INSTALL

    git clone https://github.com/ShichaoMa/exec_cmd.git
    sudo pip install -r requirements.txt

START

    ```
        # 编写配置文件，格式见host_file
        F:\projects\exec_cmd>python execute_cmd.py -h
        usage: execute_cmd.py [-h] {sftp,ssh} ...

        ssh or sftp cmd execute.

        positional arguments:
          {sftp,ssh}  cmd
            sftp      use sftp to send or receive files or floders to or from remote.
            ssh       use ssh execute cmd in remote.

        optional arguments:
          -h, --help  show this help message and exit
        Command 'sftp'
        usage: execute_cmd.py sftp [-h] [--host_file HOST_FILE] [-p]

        Command 'ssh'
        usage: execute_cmd.py ssh [-h] [--host_file HOST_FILE] [-f] [-b]

        # --host_file 指定配置文件
        # stfp 模式
        # -p 是否显示进度条
        # ssh 模式
        # -f 每个远程主机指令集是否顺序执行，或并发执行
        # -b 是否阻塞进程等待指令集执行完毕，并返回信息
    ```

