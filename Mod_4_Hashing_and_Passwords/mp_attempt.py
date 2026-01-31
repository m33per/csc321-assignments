import multiprocessing
from datetime import datetime
from bcrypt import *
import nltk
nltk.download('words')
from nltk.corpus import words

# subprocess to search a chunk of possible passwords
def search(queue, possibleWords, start, end, hashed_pws, salt):
    # loop through possible passwords
    for i in range(start, end):
        guess = hashpw(possibleWords[i].encode("utf-8"), salt)

        # check each guess with each real hashed password
        for j in range(len(hashed_pws)):
            if guess == hashed_pws[j]:
                print(f"{i}\t Password {j}: {possibleWords[i]}")
                queue.put([j, possibleWords[i], datetime.now()])

# crack passwords (of same workfactor)
def crack_passwords(possibleWords, hashed_pws, salt):
    processes = []
    queue = multiprocessing.Queue()

    # start multiple searches
    searchLocs = [0, 12514, 27029, 40543, 54058, 67572, 81087, 94601, 108116, 121630, 135145]
    for i in range(len(searchLocs) - 1):
        p = multiprocessing.Process(target=search, args=(queue, possibleWords, searchLocs[i], searchLocs[i + 1], hashed_pws, salt))
        processes.append(p)
        p.start()

    # get results
    passwords = [""] * len(hashed_pws)
    endTimes = [None] * len(hashed_pws)
    found = 0
    while found < len(hashed_pws):
        res = queue.get()
        passwords[res[0]] = res[1]
        endTimes[res[0]] = res[2]
        found += 1

    # terminate processes
    for p in processes:
        p.terminate()

    return [passwords, endTimes]


if __name__ == '__main__':

    # get list of possible words
    possibleWords = []
    for word in words.words():
        if len(word) >= 6 and len(word) <= 10:
            possibleWords.append(word)
    
    # ================================= workfactor 8 =================================
    # Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq
    # Gandalf:$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC
    # Thorin:$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q
    print("\n\nWorkfactor 8 passwords")
    hashed_pws = [b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq',
                  b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC',
                  b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q']
    salt = b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nBilbo's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
    print(f"\nGandalf's password: {res[0][1]}")
    print(f"Time: {res[1][1] - startTime}\t or {(res[1][1] - startTime).total_seconds()} seconds")
    print(f"\nThorin's password: {res[0][2]}")
    print(f"Time: {res[1][2] - startTime}\t or {(res[1][2] - startTime).total_seconds()} seconds")


    # ================================= workfactor 9 =================================
    # Fili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm
    # Kili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im
    print("\n\nWorkfactor 9 passwords")
    hashed_pws = [b'$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm',
                  b'$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im']
    salt = b'$2b$09$M9xNRFBDn0pUkPKIVCSBzu'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nFili's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
    print(f"\nKili's password: {res[0][1]}")
    print(f"Time: {res[1][1] - startTime}\t or {(res[1][1] - startTime).total_seconds()} seconds")


    # ================================= workfactor 10 =================================
    # Balin:$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom
    # Dwalin:$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be
    # Oin:$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK
    print("\n\nWorkfactor 10 passwords")
    hashed_pws = [b'$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom',
                  b'$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be',
                  b'$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK']
    salt = b'$2b$10$xGKjb94iwmlth954hEaw3O'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nBalin's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
    print(f"\nDwalin's password: {res[0][1]}")
    print(f"Time: {res[1][1] - startTime}\t or {(res[1][1] - startTime).total_seconds()} seconds")
    print(f"\nOin's password: {res[0][2]}")
    print(f"Time: {res[1][2] - startTime}\t or {(res[1][2] - startTime).total_seconds()} seconds")


    # ================================= workfactor 11 =================================
    # Gloin:$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q
    # Dori:$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq
    # Nori:$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12
    print("\n\nWorkfactor 11 passwords")
    hashed_pws = [b'$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q',
                  b'$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq',
                  b'$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12']
    salt = b'$2b$11$/8UByex2ktrWATZOBLZ0Du'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nGloin's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
    print(f"\nDori's password: {res[0][1]}")
    print(f"Time: {res[1][1] - startTime}\t or {(res[1][1] - startTime).total_seconds()} seconds")
    print(f"\nNori's password: {res[0][2]}")
    print(f"Time: {res[1][2] - startTime}\t or {(res[1][2] - startTime).total_seconds()} seconds")


    # ================================= workfactor 12 =================================
    # Ori:$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O
    # Bifur:$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK
    # Bofur:$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O
    print("\n\nWorkfactor 12 passwords")
    hashed_pws = [b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O',
                  b'$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK',
                  b'$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O']
    salt = b'$2b$12$rMeWZtAVcGHLEiDNeKCz8O'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nOri's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
    print(f"\nBifur's password: {res[0][1]}")
    print(f"Time: {res[1][1] - startTime}\t or {(res[1][1] - startTime).total_seconds()} seconds")
    print(f"\nBofur's password: {res[0][2]}")
    print(f"Time: {res[1][2] - startTime}\t or {(res[1][2] - startTime).total_seconds()} seconds")
    

    # ================================= workfactor 13 =================================
    # Durin:$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay
    print("\n\nWorkfactor 13 password")
    hashed_pws = [b'$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay']
    salt = b'$2b$13$6ypcazOOkUT/a7EwMuIjH.'
    startTime = datetime.now()
    res = crack_passwords(possibleWords, hashed_pws, salt)
    print(f"\nDurin's password: {res[0][0]}")
    print(f"Time: {res[1][0] - startTime}\t or {(res[1][0] - startTime).total_seconds()} seconds")
