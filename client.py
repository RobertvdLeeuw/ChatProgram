import socket, sys, time
from threading import Thread

from cryptography.fernet import Fernet
#import clientGUI  # 0.4 Update: Change client.py to only logic and insert IO/UI stuff in clientGUI.py

key = 0
f = 0

loggedIn = False


def sendtoserver(s):
    while True:
        argument = input('You: ')  # Password typing hiding later (when switching to GUI).
        argumentEncrypted = f.encrypt(argument.encode())

        if argument == '!c':
            print('Closing Connection...')
            s.sendall(argumentEncrypted)
            raise SystemExit

        s.sendall(argumentEncrypted)


def getfromserver(s):
    global loggedIn, f

    while True:
        rawdata = f.decrypt(s.recv(4096)).decode()

        if not rawdata:  # If it's empty
            continue

        for data in rawdata.split('&e'):  # To stop messages combining. (See server.py)
            if not data:  # If it's empty
                continue

            if len(data.split()) > 1 and data.split()[0] == '&w':
                print(f"\r{' '.join(data.split()[1::])}\nYou: ", end='')
            elif data == '&c':
                s.close()
                raise SystemExit
            elif data == '&l':
                loggedIn = True
                continue
            elif data == '&b':  # Fix input threading stuff later.
                s.sendall(f.encrypt('&_b'.encode()))
                time.sleep(0.05)
                print("\rYou've been banned from this server.")
                s.close()
                raise SystemExit
            else:
                print(f"\r{data}")
                print("\rYou: " if loggedIn else f"\r> ", end='')


if __name__ == "__main__":
    host, port = 0, 0

    try:
        host = 'localhost' if sys.argv[1] == '-L' else sys.argv[1]

        port = int(sys.argv[2])  # 12082

        f = Fernet(sys.argv[3].encode())
    except Exception as error:
        print('Invalid credentials.')
        sys.exit()


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    Thread(target=sendtoserver, args=(s, )).start()
    Thread(target=getfromserver, args=(s, )).start()
