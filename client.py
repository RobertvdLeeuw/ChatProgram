import socket, sys
from threading import Thread

closing = False
loggedIn = False

def sendtoserver(s):
    global closing

    while not closing:
        argument = input('You: ')  # Password tpying hiding later (security update).

        if argument == '!c':
            print('Closing Connection...')
            s.sendall(b'!c')
            raise SystemExit

        s.sendall(argument.encode())


def getfromserver(s):
    global closing, loggedIn

    while not closing:
        data = s.recv(4096).decode()

        if not data:
            continue

        if data == 'COMP: &c':
            s.close()
            raise SystemExit
        elif data == 'COMP: &l':
            loggedIn = True
            continue

        if loggedIn:
            print(f"\r{data}\nYou: ", end='')
        else:
            print(f"\r{data}\n> ", end='')


if __name__ == "__main__":
    host, port = 0, 0

    try:
        host = 'localhost' if sys.argv[1] == '-L' else sys.argv[1]

        port = int(sys.argv[2])  # 12082
    except:
        print('Invalid port or IP.')
        sys.exit()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    Thread(target=sendtoserver, args=(s, )).start()
    Thread(target=getfromserver, args=(s, )).start()
