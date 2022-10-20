import time
import os
import base64
import socket
import json

# local host IP '127.0.0.1' 
host = 'localhost'

# Define the port on which you want to connect 
port = 10600
path = os.getcwd()
success = 0
failure = 0
key_id = ['file:%s/test/data/key1.txt' % (path), 'file:%s/test/data/key2.txt' % (path), 'file:%s/test/data/key3.txt' % (path), 'file:%s/test/data/key4.txt' % (path),'file:%s/test/data/key5.txt' % (path),'file:%s/test/data/key6.txt' % (path)]
cipher = 'AES/KeyWrap/RFC3394NoPadding/128'
data = base64.encodestring('abcdefghijklmnopqrstuvwx')
requestEncrypt = {'request_type' : 1, 'cipher' : cipher, 'data' : data}
requestDecrypt = {'request_type' : 2, 'cipher' : cipher}
i = 0
while (i < 6):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # connect to server on local computer 
  s.connect((host,port))
  requestEncrypt['key_id'] = key_id[i]
  requestDecrypt['key_id'] = key_id[i]
  # message sent to server 
  s.send(json.dumps(requestEncrypt))

  # messaga received from server 
  message = json.loads(s.recv(1024))
  requestDecrypt['data'] = message['data']
  print '\nNew sent message'
  s.send(json.dumps(requestDecrypt))
  print 'Sent second message'
  output = json.loads(s.recv(1024))
  print 'Printing second message\n'
  print i, ' ', base64.decodestring(output['data'])
  if (output['data'] == data):
    success += 1
  else:
    failure += 1
  i += 1
  s.close()
print '(Socket Test) Wrap\Unwrap Successes: ', success, ' Wraps\Unwrap Failures: ', failure
