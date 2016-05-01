import sys
import socket
import select
from Crypto import Random
from Crypto.Cipher import AES
import base64

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

HOST = '' 
SOCKET_LIST = []
RECV_BUFFER = 4096 
PORT = 6505

class AESCipher:

    def __init__( self, key ):
        self.key = key
        
    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))
        

def dec_server():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
 
    # add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)
 
    print "The server is now online at port " + str(PORT)
 
    while 1:

        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
      
        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket: 
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                print "Client (%s, %s) connected" % addr
                 
             
            # a message from a client, not a new connection
            else: 
                try:
                    # receiving data from the socket.
                    data = sock.recv(RECV_BUFFER)
                    if data:
                         objDec = AESCipher('secretsecretsecr')
                         broadcast(sock, objDec.decrypt(data))  
                    else:
                        # remove the socket that's broken    
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        # at this stage, no data means probably the connection has been broken
                        broadcast(sock, "Client (%s, %s) is offline\n" % addr) 
 
                except:
                    broadcast(sock, "Client (%s, %s) is offline\n" % addr)
                    continue

    server_socket.close()
    
# broadcast to connected clients
def broadcast (sock, message):
    try :
        sock.send(message)
    except :
        # broken socket connection
        sock.close()
 
if __name__ == "__main__":

    sys.exit(dec_server())
