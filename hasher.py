# module
import argparse
import csv
import hashlib
import logging
import logging.handlers
import os
import sys
import time

Hasver = "1.2"
log = logging.getLogger('main._hasher')
logging.basicConfig(filename="hash.log", level=logging.DEBUG, format="%(asctime)s%(message)s")
global switch


class ClassCsv:
    def __init__(self, reportname, hashType, switch=False):
        try:
            self.csvfile = open(reportname, 'wb')
            self.writer = csv.writer(self.csvfile, delimiter=',', quoting=csv.QUOTE_ALL)
            if switch:
                self.writer.writerow(('hashtype', 'Evidence 1', 'HASH', 'Evidence2', 'HASH', 'Result'))
            else:
                self.writer.writerow(('Name', 'Path', 'Size', 'hashValue', 'Modified Time', 'Last AccessTime', 'CreatedTime',
                                      'OwnerId', 'GroupId', 'Mode'))
        except:
            log.error('CSV not formed')

    def writeRow(self, fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod):
        self.writer.writerow((fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod))

    def writeCmpRow(self, hashtype, evidence_a, hash_a, evidence_b, hash_b, res):
        self.writer.writerow((hashtype, evidence_a, hash_a, evidence_b, hash_b, res))

    def closeWriter(self):
        self.csvfile.close()


def init(parser):
    global glArgs
    global glHashType
    glArgs = parser
    if glArgs.md5:
        glHashType = 'MD5'
    elif glArgs.sha256:
        glHashType = 'SHA256'
    elif glArgs.sha512:
        glHashType = 'SHA512'
    else:
        glHashType = "Unknown"
        logging.error("Unknown Hash type specified ")
    PrintMessage("VERSION:" + Hasver)
    PrintMessage("Command line processed :Successfully")
    PrintMessage("\nPARSED ARGUMENTS:  \n"+str(glArgs)[10:-1:])
    PrintMessage("\nHASH TYPE:   \n"+str(glHashType))
    return


def Valid_Dir(dir):
    if not os.path.isdir(dir):
        raise argparse.ArgumentTypeError("Specified Directory does not exist")
    return str(dir)


def Valid_Dir_writable(dir):
    if os.access(dir, os.W_OK):
        return str(dir)
    else:
        raise argparse.ArgumentTypeError('Directory is not writable ')


def parserme():
    #parentParser
    parser = argparse.ArgumentParser(prog='Evidence Integrity Checker \n' + Hasver)
    parser.add_argument('-v', '--verbose', action='store_true', help='For verbosity ')
    subparsers = parser.add_subparsers()
    # create the parser for the "c" command
    s = """Comparing Hashes Usage -c -a[Path First Evidence]-b[Path Second Evidence]-r[Path to Store Result CSV](-md5|-sha256|-sha512)"""
    parser_compare = subparsers.add_parser('c', help=s)
    parser_compare.add_argument('-a', '--evidence1', type=Valid_Dir, required=True,
                                help="Enter the Root path for First Evidence ")
    parser_compare.add_argument('-b', '--evidence2', type=Valid_Dir, required=True,
                                help="Enter the Root path for Second Evidence")
    parser_compare.add_argument('-r', '--report', type=str, required=Valid_Dir_writable,
                                help="Enter Path To Store CSV Report")
    group = parser_compare.add_mutually_exclusive_group(required=True)
    group.add_argument('-md5', help='specifies md5 algorithm', action='store_true')
    group.add_argument('-sha256', help='specifies sha256 algorithm', action='store_true')
    group.add_argument('-sha512', help='specifies SHA512 algorithm', action='store_true')
    # create the parser for the "m" command
    d = """Making Hashes \n Usage eg -md5|-sha256|-sha512 -d[Evidence Path] -r[Path For Generated Csv]"""
    parser_make = subparsers.add_parser('m', help=d)
    parser_make.add_argument('-d', '--rootPath', type=Valid_Dir, required=True, help="enter the root path for hashing ")
    parser_make.add_argument('-r', '--report', type=Valid_Dir_writable, required=True,
                             help='enter location for CSV Report')
    group = parser_make.add_mutually_exclusive_group(required=True)
    group.add_argument('-md5', help='specifies md5 algorithm', action='store_true')
    group.add_argument('-sha256', help='specifies sha256 algorithm', action='store_true')
    group.add_argument('-sha512', help='specifies SHA512 algorithm', action='store_true')
    s = parser.parse_args()
    d = vars(s)
    if "rootPath" in d:
        init(s)
        PrintMessage("\nCreating Hashes:\n")
        logger(Go())
    elif "evidence1" in d:
        init(s)
        PrintMessage("\nComparing Hashes:\n")
        logger(Go2())



def logger(func):
    startTime = time.time()
    logging.info('')
    logging.info("New Scans Started ")
    logging.info(" System: " + sys.platform)
    logging.info(" Version " + Hasver)
    filesdone = func
    endtime = time.time()
    duration = endtime - startTime
    logging.info("Time Taken :" + str(duration))
    logging.info("file Processed Count:" + str(filesdone))
    logging.info('')
    PrintMessage("\nCHECK CSV FILE:\n"+str(glArgs.report))
    logging.shutdown()


def PrintMessage(msg):
    if glArgs.verbose:
        print(msg)


def Hasher(filepath, Name, result):
    if os.path.exists(filepath):
        if not os.path.islink(filepath):
            if os.path.isfile(filepath):
                try:
                    f = open(filepath, 'rb')
                    PrintMessage("\nFILE PATH:\n" + filepath)
                    PrintMessage("\nPROCESSING FILE:\n" + Name)
                except IOError:
                    log.warning("Opened Filed:" + filepath)
                    return
                else:
                    try:
                        rd = f.read()
                        PrintMessage("\nCONTENT:\n"+rd)

                    except IOError:
                        f.close()
                        log.warning('Read Failed' + filepath)
                        return
                    else:
                        (mode, ino, dev, link, uid, gid, size, atime, mtime, createtime) = os.stat(filepath)
                        filesize = str(size)
                        modifiedTime = time.ctime(mtime)
                        accessTime = time.ctime(atime)
                        createdTime = time.ctime(createtime)
                        ownerID = str(uid)
                        groupID = str(gid)
                        fileMode = oct(mode)
                    if glArgs.md5:
                        hash = hashlib.md5()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    elif glArgs.sha256:
                        hash = hashlib.sha256()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    elif glArgs.sha512:
                        hash = hashlib.sha512()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    else:
                        log.error('hash not selected')
                    f.close()
                    result.writeRow(Name, filepath, filesize, value, modifiedTime, accessTime, createdTime, ownerID,
                                    groupID, fileMode)
                    return True
            else:
                log.warning('****' + repr(Name) + '****' + 'Not a File')
        else:
            log.warning('****' + repr(Name) + '****' + 'Not a link')
    else:
        log.warning('****' + repr(Name) + '****' + 'Not a Path')
        return False


def Go():
    pC = 0  #number of processed files
    eC = 0  #number of errors
    log.info('Root Path:' + glArgs.rootPath)
    ocvs = ClassCsv(glArgs.report + 'HashReport.csv', glHashType)
    for root, dirs, files in os.walk(glArgs.rootPath):
        for file in files:
            filepath = os.path.join(root, file)
            result = Hasher(filepath, file, ocvs)
            if result is True:
                pC += 1
            else:
                eC += 1
                PrintMessage("ERROR COUNT"+str(eC))
            ocvs.closeWriter()
    PrintMessage("\nFILE PROCESSED:\n"+str(pC))
    return (pC)


def hashcmp(filepath, file):
    if os.path.exists(filepath):
        if not os.path.islink(filepath):
            if os.path.isfile(filepath):
                try:
                    f = open(filepath, 'rb')
                    print("\nFile Path:  \n" + filepath)
                except IOError:
                    log.warning("Opened Filed:" + filepath)
                    return
                else:
                    try:
                        rd = f.read()
                        PrintMessage("\nFILE CONTENT:\n" + rd )
                    except IOError:
                        f.close()
                        log.warning('Read Failed' + filepath)
                        return
                    else:
                        PrintMessage("\nPROCESSING FILE:\n" + file)
                    if glArgs.md5:
                        hash = hashlib.md5()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    elif glArgs.sha256:
                        hash = hashlib.sha256()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    elif glArgs.sha512:
                        hash = hashlib.sha512()
                        hash.update(rd)
                        hex = hash.hexdigest()
                        value = hex.upper()
                    else:
                        log.error('hash not selected')
                    f.close()
                    return value
            else:
                log.warning('****' + repr(file) + '****' + 'Not a File')
        else:
            log.warning('****' + repr(file) + '****' + 'Not a link')

    else:
        log.warning('****' + repr(file) + '****' + 'Not a Path')
        return False


def Go2():
    processCount = 0
    log.info('Report Path:' + glArgs.report)
    ocvs = ClassCsv(glArgs.report + 'HashCompare.csv', glHashType, True)
    for root, dirs, files in os.walk(glArgs.evidence1):
        for file in files:
            filepath = os.path.join(root, file)
            result1 = hashcmp(filepath, file)
            PrintMessage("\nHEX VALUE:\n"+result1)

    for root, dirs, files in os.walk(glArgs.evidence2):
        for file in files:
            filepath = os.path.join(root, file)
            result2 = hashcmp(filepath, file)
            PrintMessage("\nHEX VALUE:\n"+result2)
    if result1 == result2:
        ans = "True"
        processCount += 1
    else:
        ans = "False"
    PrintMessage("\nRESULT:\n"+ans)
    ocvs.writeCmpRow(glHashType, glArgs.evidence1, result1, glArgs.evidence2, result2, ans)
    ocvs.closeWriter()
    return (processCount)
