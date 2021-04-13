import socket, time
from threading import Thread
from requests import get

IP = get('https://api.ipify.org').text

Host, Port = socket.gethostbyname(socket.gethostname()), 12082

Connections = dict()

CachedMessage = ('', '')  # Takes <1ms to get done, so that's why this isn't a queue. Add more?
MessageDone = list()  # List of all connections that finished this message. Empties both when full. (data, address)


def thread_accept():
    global s, Connections

    while True:  # Threading? Only send upon receive!
        conn, addr = s.accept()
        Connections[addr] = conn

        Thread(target=thread_recv, args=(conn, addr)).start()

        conn.send(str.encode('Welcome to the Server'))


def thread_recv(connection, address):
    global Connections, CachedMessage

    while True:
        data = connection.recv(4096)

        if not data:
            continue

        if data == 'close':
            print(f'{address} left the chat.')
            Connections.pop(address)
            s.close()
            break
        else:
            while CachedMessage != ('', ''):
                pass
            CachedMessage = (data, address)


def thread_main():
    global s, Connections
    global CachedMessage, MessageDone

    try:
        while True:
            if len(Connections) > 0:  # For the 'No connections' stuff
                if CachedMessage != ('', ''):
                    (data, fromaddress) = CachedMessage
                    data = data.decode()
                    print(f"{fromaddress}: {data}")

                    # Caching message for others to see
                    if len(Connections) > 1:
                        for toaddress in Connections.keys():  # Only other address (never fromaddress).
                            if toaddress == fromaddress:  # So we don't send back to the sender
                                MessageDone.append(toaddress)
                                continue

                            if toaddress not in MessageDone:  # If it hasn't been sent to this address yet.
                                Connections[toaddress].sendto(F"{toaddress[1]}: {data}".encode(), toaddress)
                                MessageDone.append(toaddress)


                    print(f'Clear: {CachedMessage}')
                    CachedMessage = ('', '')
                    MessageDone = list()

        else:
            time.sleep(1)
            print('No connections.')
    except:
        pass




if __name__ == "__main__":
    print(f"Your public IP is {IP}.")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((Host, Port))
    s.listen(32)

    Thread(target=thread_accept).start()
    Thread(target=thread_main).start()
