import socket, time, sys
from threading import Thread

Host, Port = "localhost", 12082
Closing = False


def sendtoserver(s):
    global Closing

    while not Closing:
        argument = input('You: ')

        if argument == 'close':
            print('Closing Connection...')
            s.sendall(b'close')
            Closing = True
            raise SystemExit

        s.sendall(argument.encode())


def getfromserver(s):
    global Closing

    while not Closing:
        data = s.recv(4096)
        if not data:
            continue

        print(data.decode())


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Host = sys.argv[1]
    else:
        print('No IP specified.')
        sys.exit()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((Host, Port))

    data = s.recv(4096)
    s.sendall(b'Test.')

    Thread(target=sendtoserver, args=(s, )).start()
    Thread(target=getfromserver, args=(s, )).start()
