#!coding=utf-8

import sys
import struct
import hashlib

from base64 import(
    b64encode,
    b64decode,
)
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

class Gram:
    gramHead = 0
    repoSize = 0
    repo = ""
    repoHash = ""
    valid = False

class RemoteEnd:

    # class CpuInfo:
    #     def __init__(self, raw):
    #         self.cpuUsage = raw

    # class MemInfo:
    #     def __init__(self, raw):
    #         self.memUsage = raw

    # class DisakInfo:
    #     def __init__(self, raw):
    #         self.diskUsage = raw

    class SysInfo:
        osType = ""
        release = ""
        kernel = ""
    
    class NetInfo:
        localIp = ""
        localPort = 0
        remoteIp = ""
        remotePort = 0
        status = ''

    ID = 0
    statusLevel = 0

    cpuInfo = 0.0
    memInfo = 0.0
    diskInfo = 0.0
    openedPort = []
    
    def __init__(self):
        pass
    
    def setCpuInfo(self, usage):
        self.cpuInfo = usage
    
    def setMemInfo(self, usage):
        self.memInfo = usage

    def setDiskInfo(self, usage):
        self.diskInfo = usage
    
    def setNetInfo(self, netInfo):
        self.openedPort.append(netInfo)
        pass
    
    def setSysInfo(self, os, release, kernel):
        self.sysInfo = RemoteEnd.SysInfo()
        self.sysInfo.osType = os
        self.sysInfo.release = release
        self.sysInfo.kernel = kernel

class CA:

    def __init__(self):
        self.gram = Gram()

    def readReport(self):
        fp = open("./report", "rb")
        self.gram.gramHead = struct.unpack('I', fp.read(4))[0]
        self.gram.repoSize = struct.unpack('I', fp.read(4))[0]
        self.gram.repo = fp.read(self.gram.repoSize)
        self.gram.repoHash = fp.read(20)

    def isReportChanged(self, detail):
        digest = SHA.new()
        digest.update(detail)
        if digest.digest() == self.gram.repoHash:
            self.gram.valid = True
            return True
        else:
            self.gram.valid = False
            return False

    def analysisReportT(self, detail):
        self.remoteEnd = RemoteEnd()

        a = detail[0:80]
        b = detail[80:160]
        c = detail[160:240]
        
        self.remoteEnd.setSysInfo(a, b, c)

        d = struct.unpack('f', detail[240:244])[0]
        self.remoteEnd.setCpuInfo(d)

        e = struct.unpack('f', detail[244:248])[0]
        self.remoteEnd.setMemInfo(e)

        f = struct.unpack('f', detail[248:252])[0]
        self.remoteEnd.setDiskInfo(f)

        openedPortNum = struct.unpack('I', detail[252:256])[0]

        offset = 256
        for i in range(0,openedPortNum - 1):
            g = detail[offset:offset+31]
            offset += 31
            h = g.split('\0')
            if len(h) != 4:
                print "Error"
                continue
            netInfo = RemoteEnd.NetInfo()
            j = h[0].split(':')
            netInfo.localIp = j[0]
            netInfo.localPort = int(j[1], 16)
            
            l = h[1].split(':')
            netInfo.remoteIp = l[0]
            netInfo.remotePort = int(l[1], 16)

            netInfo.status = h[2]
            self.remoteEnd.setNetInfo(netInfo)

    def display(self):
        print "----------------------"
        print "[Usage]\ncpu:" + str(self.remoteEnd.cpuInfo) + " mem:" \
                        + str(self.remoteEnd.memInfo) + " disk" + str(self.remoteEnd.diskInfo)
        for each in self.remoteEnd.openedPort:
            print "[Net] Port:" + str(each.localPort) + "|" + str(each.remotePort) + "|" + str(each.status)
        
    def createCerSrouce(self):
        timeOfValid = {
            0: 10,
            1: 5,
            2: 3,
            4: 1
        }[self.remoteEnd.statusLevel]
        import time
        timeStamp =  int(round(time.time()))
        return struct.pack("<I", self.remoteEnd.ID) + struct.pack("<I", self.remoteEnd.statusLevel) + \
                    struct.pack("<I", timeStamp) + struct.pack("<L", timeOfValid)

    def issueCertificate(self, source):
        digest = SHA.new()
        digest.update(source)

        with open("./rsa_private_key.pem", "r") as privKeyFile:
            privKey = RSA.importKey(privKeyFile.read())
        
        signer = PKCS1_v1_5.new(privKey)
        sig = signer.sign(digest)

        return struct.pack('<L', len(source)) + source + sig
        

if __name__ == "__main__":
    import time
    start = time.clock()
    ca = CA()
    ca.readReport()
    ca.analysisReportT(ca.gram.repo)

    source = ca.createCerSrouce()
    open("tc", "wb").write(ca.issueCertificate(source))
    elapsed = (time.clock() - start)
    print elapsed
