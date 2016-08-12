import socket
import threading

class netInput(threading.Thread):
        def __init__(self, port, s):
                threading.Thread.__init__(self)
                self.port = port
                self.isDead = False
                self.s = s;

        def run(self):
                print("Starting to listen to port " + str(self.port))
                while self.isDead != True:
                        data, address = self.s.recvfrom(1024)
                        data = data.decode('utf-8')
                        print(str(address)+": " + data)

                print("Stopped listening port "+str(self.port))

        def kill(self):
                self.isDead = True;

def main():
        host = '10.100.102.71'
        print("Please enter Port for your side")
        port = int(input(" ---> "))

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host,port))

        print("Please enter IP address to connect")
        p_ip = input(" ---> ")
        print("Please enter Port")
        p_port = int(input(" ---> "))
        l = netInput(port, s)

        target = (p_ip,p_port)
        l.start()
        print("Type --kill to end transsmition")
        message = input("---> ")
        while message != '--kill':
                s.sendto(message.encode("utf-8"), target)
                message = input("---> ")
	
        l.kill()
        s.sendto("<<Transsmition End>>".encode("utf-8"), target)
        s.close()
		

if __name__ == '__main__':
    main()
	s.close
