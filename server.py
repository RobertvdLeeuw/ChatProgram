import socket, sys, time
from datetime import datetime, timedelta
from enum import Enum
from threading import Thread
from requests import get

from cryptography.fernet import Fernet

key = Fernet.generate_key()
f = Fernet(key)

host, port = 0, 0
superUserPassword = ''

# &e = message end, to stop 2 messages sent after one another to get combined without using async (it splits in client.py).

users = list()  # All users, active and inactive.

connections = dict()  # address: connection
activeUsers = dict()  # address: user

bannedIPs = list()  # address[0]


class Restriction(Enum):  # Might turn into flag later
    none = 0
    ban = 1
    timeout = 2
    slowmode = 3
    readonly = 4
    nofiles = 5  # Can't share files


class User:  # Change attr(?)+, delete self?
    global users, connections
    global f

    lastAddress = 0  # Used for unbanning purposes
    currentAddress = 0  # Also used to check if account is active/logged in.

    flagType = Restriction.none  # Flagged for timeout, slowmode, etc.
    restrictionTimer = 0  # Time (in seconds) that user is timed out, or between each message in the case of slow mode
    lastMessagedTime = 0  # For slowmode or timeout

    def __init__(self, name, password, address):
        self.name = name  # Since all names must be unique, there's no need for a separate id.
        self._password = password

        self.login(address, name, password)

    def login(self, address, username, password):  # Logs in, if possible, and sends back whether successful.
        correctInfo = self.name == username and self._password == password
        alreadyActive = self.currentAddress != 0

        if correctInfo and not alreadyActive:
            self.currentAddress = address

            self.send('&l')  # Command to tell the client they're logged in.
            print(f"{self.name}: {self.currentAddress}.")  # Server side
            time.sleep(0.05)  # Sleeping might not be the best solution, but I can't be fucked to use async + threading (yet).
            self.send(f'Welcome, {self.name}.')
            self.sendToAll(message=f'{self.name} entered the chat.', noname=True)

        return correctInfo and not alreadyActive

    def logout(self, banned=False):
        self.sendToAll(message=f'{self.name} has been banned from the chat.' if banned else f'{self.name} left the chat.', noname=True)  # Turn into switch-case when more logout options are added (e.g. timeout).
        self.send('&b' if banned else '&c')

        connections[self.currentAddress].close()
        activeUsers.pop(self.currentAddress)
        connections.pop(self.currentAddress)

        self.lastAddress, self.currentAddress = self.currentAddress, 0
        print(f'{self.name} logged out.')  # Server side

    def send(self, message):  # Wrapping connection.sendall() so that all actions are done through the user, not some user and some connection.
        connections[self.currentAddress].sendall(f.encrypt(f"{message}&e".encode()))

    def whisper(self, username, message):
        if user := getUser(username):
            connections[user.currentAddress].sendall(f.encrypt(f"&w {self.name} (whispered): {message}&e".encode()))

    def sendToAll(self, message, noname=False):  # Send message to all others in the chat.
        if len(connections) > 1:
            for toAddress in [x for x in activeUsers.keys() if x != self.currentAddress]:  # So we don't send back to the sender
                data = f"{message}&e" if noname else f"{self.name}: {message}&e"
                connections[toAddress].sendall(f.encrypt(data.encode()))


class SuperUser(User):
    global activeUsers
    global bannedIPs

    def ban(self, username):
        if user := getUser(username):
            bannedIPs.append(user.currentAddress[0])  # [0] To just take IP, not the port - which changes upon reconnection.
            user.logout(banned=True)
            user.flagged = Restriction.ban

            return
        self.send('No user was found with that name.')

    def unban(self, username):
        if user := getUser(username):
            bannedIPs.remove(user.lastAddress[0])
            user.flagged = Restriction.none
            self.send(f'{user.name} has been unbanned. No one else can see this message.')

    def slowmode(self, username, timelength):
        if user := getUser(username):
            user.flagged = True
            user.restrictionTimer = int(timelength)

    def timeout(self, username, timelength):
        if user := getUser(username):
            user.flagged = True
            user.restrictionTimer = int(timelength)


def getInput(connection, message):  # Networking version of input(message). FP and not OOP, because this function is only used by clients who haven't been assigned to users yet.
    global f
    connection.sendall(f.encrypt(f"{message}&e".encode()))
    return f.decrypt(connection.recv(4096)).decode()


def getUser(username):
    for userCheck in users:
        if userCheck.name == username:
            return userCheck
    return False


def userLogin(connection, address):  # Logging in (or registering).
    global users, activeUsers
    global f, superUserPassword

    while True:
        option = getInput(connection, 'Select option: (L)ogin, (R)egister, (S)uperuser registration.')

        if option == 'R' or option == 'S':  # Registering
            if option == 'S':
                suPassword = getInput(connection, 'Enter superuser password:')

                if suPassword != superUserPassword:
                    connection.sendall(f.encrypt('Incorrect SUP.'.encode()))
                    break

            username = getInput(connection, 'Set username:')
            password = getInput(connection, 'Set password:')

            if username == 'You' or username[0] == '!' or username[0] == '&':
                connection.sendall(f.encrypt("Don't make this more confusing for others.&e".encode()))
                time.sleep(0.05)
                continue
            elif len(username.split()) > 1:
                connection.sendall(f.encrypt("Sorry, but you can't have spaces in your username.&e".encode()))
                time.sleep(0.05)
                continue

            if getUser(username) is False:
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
                connection.sendall(f.encrysendpt('No accounts have been registered on this server yet.'.encode()))
        time.sleep(0.05)


def thread_recv(connection, address):  # Receiving messages from clients, and caching them to send to others.
    global connections
    global f

    user = userLogin(connection, address)

    while True:
        data = f.decrypt(connection.recv(4096)).decode()

        if not data:  # If it's empty
            continue

        '''try:
            if user.flagType is not Restriction.none:  # Restrictions
                if datetime.now() - user.lastMessagedTime < timedelta(seconds=user.restrictionTimer):
                    user.send("Sorry, but you can't send anything right now")  # Make more clear later (type of restriction).
                    continue
        except:
            print(user)'''  # Continue on this alter

            # Clean this all once switch cases are implemented
        if data == '&_b':  # Ban conformation from user end (also needed to close on user end).
            break
        elif data[0] == '&':
            user.send("Unable to send message (cannot start with '&', seeing at that is used to server commands).")
        elif data[0] == '!':
            if data == '!c':  # Need...switch cases...
                user.logout()
                break
            elif data == '!h':
                user.send('  !h: help\n  !c: close\n  !w <username>: whisper to user\n  !f <filepath>: share a file (TBI)' +
                          ('' if not isinstance(user, SuperUser) else
                          '\n  !b <username>: ban user\n  !B <username>: unban user'
                          '\n  !t <username> <seconds>: timeout user (TBI)\n  !s <username> <seconds>: slowmode chat on user (TBI)'))
            elif data.split()[0] == '!w':
                user.whisper(data.split()[1], ' '.join(data.split()[2::]))
            elif data.split()[0] == '!b' or data.split()[0] == '!B':  # If the first argument is '!b' or '!B'
                if isinstance(user, SuperUser):
                    if len(data.split()) == 2:
                        if data.split()[0] == '!b':
                            user.ban(data.split()[1])
                        else:
                            user.unban(data.split()[1])
                    else:
                        user.send('Too many or too few arguments given.')
                else:
                    user.send("You don't have permission to use this function.")
            elif data.split()[0] == '!f':
                if user.flagType != Restriction.nofiles:
                    if len(data.split()) == 2:
                        pass  # Get file, store somehow
                    else:
                        user.send('Too many or too few arguments given.')
                else:
                    user.send("You don't have permission to use this function.")
            else:
                user.send('Command not found. Type !h for help')
        else:
            user.sendToAll(data)


def thread_accept():  # Accepting new connections.
    global s, connections
    global f

    while True:
        conn, addr = s.accept()
        connections[addr] = conn

        if addr[0] not in bannedIPs:
            Thread(target=thread_recv, args=(conn, addr)).start()
        else:
            conn.sendall(f.encrypt("&b".encode()))  # Not tested/implemented completely yet.


if __name__ == "__main__":
    if len(sys.argv) >= 4:  # Rewrite to a nice, clean match case once available
        if sys.argv[1] == '-L':
            host = 'localhost'
        elif sys.argv[1] == '-W':
            host = socket.gethostbyname(socket.gethostname())
        else:
            print('Invalid IP argument.')
            sys.exit()

        port = int(sys.argv[2])  # 12082

        superUserPassword = sys.argv[3]

        fileSharing = '-F' in sys.argv

        if '-C' in sys.argv: # For later
            import pyperclip3
            pyperclip3.copy(key.decode())

        '''if fileSharing:
            filePath = sys.argv[5] if os.path.isabs(filePath) else ''  # Finish this later.'''
    else:
        print('Too few arguments.')
        sys.exit()

    if sys.argv[1] == '-W':
        print(f"Public: {get('https://api.ipify.org').text}, Private: {socket.gethostbyname(socket.gethostname())}.")
    print(f"Key: {key.decode()}")


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(32)

    Thread(target=thread_accept).start()
