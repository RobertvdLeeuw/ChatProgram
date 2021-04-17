import socket, sys, time
from threading import Thread
from requests import get


# ! is user commands, & is computer commands

users = list()  # All users, active and inactive.

connections = dict()  # address: connection
activeUsers = dict()  # address, user

bannedIPs = list()  # address[0]


class User:  # Permissions(?), send to specific(?), change attr(?)
    global users, connections

    currentAddress = 0  # Also used to check if account is active/logged in.
    lastMessagedTime = 0  # Not in use yet, for later.

    def __init__(self, name, password, address):
        self.name = name # Since all names must be unique, there's no need for a separate id.
        self._password = password
        self.currentAddress = address

    def login(self, address, username, password):  # Logs in, if possible, and sends back whether successful.
        correctInfo = self.name == username and self._password == password
        alreadyActive = self.currentAddress != 0

        if not alreadyActive and correctInfo:
            self.currentAddress = address
            print(f'{self.name} logged in.')

        return canLogIn

    def logout(self):
        self.currentAddress = 0
        print(f'{self.name} logged out.')

    def send(self, message):  # Wrapping connection.sendall() so that all actions are done through the user, not some user and some connection.
        connections[self.currentAddress].sendall(message.encode())

    def sendToOthers(self, message):  # Send message to all others in the chat.
        if len(connections) > 1:
            for toAddress in activeUsers.keys():
                if toAddress != self.currentAddress:  # So we don't send back to the sender
                    connections[toAddress].sendall(message.encode())


class SuperUser(User):
    global connections, bannedIPs

    '''def ban(self, user):
        bannedIPs.append(user.currentAddress[0])
        connections[user.currentAddress].close()  # Expand later


        del user'''

    def kick(self, user):
        pass

    def promote(self, user):
        pass

    def demote(self, superuser):  # Needed?
        pass

    def restrict(self, user):  # Needed?
        pass


def getInput(connection, message):  # Networking version of input(message). FP and not OOP, because this function is only used by clients who haven't been assigned to users yet.
    connection.sendall(message.encode())
    return str(connection.recv(4096).decode())


def userLogin(connection, address):  # Logging in (or registering).
    global users, activeUsers

    user = 0

    while True:
        option = getInput(connection, 'Select option: (L)ogin, (R)egister.')

        if option == 'R':  # Registering
            username = getInput(connection, 'Set username:')
            password = getInput(connection, 'Set password:')

            if username == 'You':
                connection.sendall("Don't make this more confusing for others.".encode())
                time.sleep(0.05)
                continue
            elif username == 'COMP':
                connection.sendall("That name is reserved.".encode())
                time.sleep(0.05)
                continue

            if username not in list(map(lambda x : x.name, users)):
                user = User(username, password, address)
                users.append(user)
                activeUsers[address] = user

                return user
            else:
                connection.sendall('Username taken, try again.'.encode())
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
                connection.sendall('Login failed, please try again.'.encode())
            else:
                connection.sendall('No accounts have been registered on this server yet.'.encode())
        time.sleep(0.05)


def thread_recv(connection, address):  # Receiving messages from clients, and caching them to send to others..
    global connections

    user = userLogin(connection, address)

    user.send('COMP: &l')  # Command to tell the client they're logged in.
    time.sleep(0.05)  # Sleeping might not be the best solution, but I can't be fucked to use async + threading.
    user.send(f'Welcome, {user.name}')
    user.sendToOthers(f'{user.name} entered the chat.')

    while True:
        data = connection.recv(4096).decode()

        if not data:
            continue

        if data == '!c':
            user.sendToOthers(f'{user.name} left the chat.')
            user.send('COMP: &c')
            user.logout()

            connections.pop(address)
            connection.close()
            break
        elif data == '!h':
            user.send('!h: help\n!c: close')

        else:
            user.sendToOthers(f"{user.name}: {data}")


def thread_accept():  # Accepting new connections.
    global s, connections

    while True:
        conn, addr = s.accept()
        connections[addr] = conn

        if addr[0] not in bannedIPs:
            Thread(target=thread_recv, args=(conn, addr)).start()
        else:
            conn.sendall("Your IP has been banned from this server.".encode())  # Not tested/implemented completely yet.


if __name__ == "__main__":
    host, port = 0, 0

    try:
        if sys.argv[1] == '-L':
            host = 'localhost'
        elif sys.argv[1] == '-W':
            host = socket.gethostbyname(socket.gethostname())

        port = int(sys.argv[2])  # 12082
    except:
        print('Invalid port or IP.')
        sys.exit()

    print(f"Public: {get('https://api.ipify.org').text}, Private: {host}.")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(32)

    Thread(target=thread_accept).start()
