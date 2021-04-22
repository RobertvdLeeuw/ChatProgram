import socket, sys, time
from threading import Thread
from requests import get

from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)

host, port = 0, 0
superUserPassword = ''

# &e = message end, to stop 2 messages sent after one another to get combined without using async.

users = list()  # All users, active and inactive.

connections = dict()  # address: connection
activeUsers = dict()  # address, user

bannedIPs = list()  # address[0]


class User:  # Permissions(?), send to specific(?), change attr(?)
    global users, connections
    global f

    currentAddress = 0  # Also used to check if account is active/logged in.
    lastMessagedTime = 0  # Not in use yet, for later.

    def __init__(self, name, password, address):
        self.name = name # Since all names must be unique, there's no need for a separate id.
        self._password = password

        self.login(address, name, password)

    def login(self, address, username, password):  # Logs in, if possible, and sends back whether successful.
        correctInfo = self.name == username and self._password == password
        alreadyActive = self.currentAddress != 0

        if correctInfo and not alreadyActive:
            self.currentAddress = address

            self.send('&l')  # Command to tell the client they're logged in.
            print(f"{self.name}: {self.currentAddress}.")
            time.sleep(0.05)  # Sleeping might not be the best solution, but I can't be fucked to use async + threading (yet).
            self.send(f'Welcome, {self.name}')
            self.sendToAll(f'{self.name} entered the chat.')

        return correctInfo and not alreadyActive

    def logout(self, banned=False):
        self.sendToAll(f'{self.name} has been banned from the chat.' if banned else f'{self.name} left the chat.')
        self.send('&b' if banned else '&c')

        connections[self.currentAddress].close()
        activeUsers.pop(self.currentAddress)
        connections.pop(self.currentAddress)

        self.currentAddress = 0
        print(f'{self.name} logged out.')

    def send(self, message):  # Wrapping connection.sendall() so that all actions are done through the user, not some user and some connection.
        connections[self.currentAddress].sendall(f.encrypt(f"{message}&e".encode()))

    def sendToAll(self, message):  # Send message to all others in the chat.
        if len(connections) > 1:
            for toAddress in activeUsers.keys():
                if toAddress != self.currentAddress:  # So we don't send back to the sender
                    connections[toAddress].sendall(f.encrypt(f"{message}&e".encode()))


class SuperUser(User):
    global activeUsers
    global bannedIPs

    def ban(self, username):
        user = 0
        userAddress = 0

        for userCheck in users:
            if userCheck.name == username:
                user = userCheck
                userAddress = user.currentAddress
                break

        if user == 0:
            self.send('No user was found with that name.')
            return

        bannedIPs.append(user.currentAddress[0])
        user.logout(banned=True)

        del user


def getInput(connection, message):  # Networking version of input(message). FP and not OOP, because this function is only used by clients who haven't been assigned to users yet.
    global f
    connection.sendall(f.encrypt(f"{message}&e".encode()))
    return f.decrypt(connection.recv(4096)).decode()


def userLogin(connection, address):  # Logging in (or registering).
    global users, activeUsers
    global f, superUserPassword

    user = 0

    while True:
        option = getInput(connection, 'Select option: (L)ogin, (R)egister, (S)uperuser registration.')

        if option == 'S':
            suPassword = getInput(connection, 'Enter superuser password:')

            if suPassword == superUserPassword:
                username = getInput(connection, 'Set username:')
                password = getInput(connection, 'Set password:')

                if username == 'You':
                    connection.sendall(f.encrypt("Don't make this more confusing for others.&e".encode()))
                    time.sleep(0.05)
                    continue

                if username not in list(map(lambda x : x.name, users)):
                    user = SuperUser(username, password, address)
                    users.append(user)
                    activeUsers[address] = user

                    return user
        if option == 'R' or option == 'S':  # Registering
            if option == 'S':
                suPassword = getInput(connection, 'Enter superuser password:')

                if suPassword != superUserPassword:
                    break

            username = getInput(connection, 'Set username:')
            password = getInput(connection, 'Set password:')

            if username == 'You':
                connection.sendall(f.encrypt("Don't make this more confusing for others.&e".encode()))
                time.sleep(0.05)
                continue

            if username not in list(map(lambda x : x.name, users)):
                user = User(username, password, address) if option == 'R' else SuperUser(username, password, address)
                users.append(user)
                activeUsers[address] = user

                return user
            else:
                connection.sendall(f.encrypt('Username taken, try again.'.encode()))
        elif option == 'L':  # Logging in
            if len(users) > 0:
                username = getInput(connection, 'Username:')
                password = getInput(connection, 'Password:')

                for checkUser in users:
                    if checkUser.login(address, username, password):
                        users.append(checkUser)
                        activeUsers[address] = checkUser
                        user = checkUser

                        return user
                connection.sendall(f.encrypt('Login failed, please try again.'.encode()))
            else:
                connection.sendall(f.encrypt('No accounts have been registered on this server yet.'.encode()))
        time.sleep(0.05)


def thread_recv(connection, address):  # Receiving messages from clients, and caching them to send to others..
    global connections
    global f

    user = userLogin(connection, address)

    while True:
        data = f.decrypt(connection.recv(4096)).decode()

        if not data:
            continue

        if data == '!c':
            user.logout()
            break
        elif data == '!h':
            if isinstance(user, SuperUser):
                user.send('  !h: help\n  !c: close\n  !b <username>: ban user')
            else:
                user.send('  !h: help\n  !c: close')
        elif data == '&_b':
            break
        elif data.split()[0] == '!b': # If the first argument is '!b'
            if isinstance(user, SuperUser):
                if len(data.split()) == 2:
                    user.ban(data.split()[1])
                else:
                    user.send('Too many or too few arguments given.')
            else:
                user.send("You don't have permission to use this function.")
        else:
            user.sendToAll(f"{user.name}: {data}")


def thread_accept():  # Accepting new connections.
    global s, connections
    global f

    while True:
        conn, addr = s.accept()
        connections[addr] = conn

        if addr[0] not in bannedIPs:
            Thread(target=thread_recv, args=(conn, addr)).start()
        else:
            conn.sendall(f.encrypt("Your IP has been banned from this server, fucko!".encode()))  # Not tested/implemented completely yet.


if __name__ == "__main__":
    if len(sys.argv) == 4:
        if sys.argv[1] == '-L':
            host = 'localhost'
        elif sys.argv[1] == '-W':
            host = socket.gethostbyname(socket.gethostname())
        else:
            print('Invalid IP argument.')
            sys.exit()

        port = int(sys.argv[2])  # 12082

        superUserPassword = sys.argv[3]
    else:
        print('Too many or too few arguments.')
        sys.exit()

    if sys.argv[1] == '-W':
        print(f"Public: {get('https://api.ipify.org').text}, Private: {socket.gethostbyname(socket.gethostname())}.")
    print(f"Key: {key.decode()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(32)

    Thread(target=thread_accept).start()
