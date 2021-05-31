# ..... LSABE module frontend (aka command line and arguments processing) ......

import os
import io
import time
import argparse
import pathlib
import random
import string
from typing import Text
import requests
from base64 import b64encode
from .arguments import arguments_setup, dir_create
from .lsabe_ma import LSABE_MA
from .lsabe_authority import LSABE_AUTH
from .feRoutines import *

def startup():

    MAX_KEYWORDS = 10
    parser = arguments_setup(MAX_KEYWORDS)
    args = parser.parse_args()

    if (not args.global_setup_flag and 
        not args.authority_setup_flag and 
        not args.keygen_flag and 
        not args.encrypt_flag and 
        not args.search_flag and 
        not args.clear_flag and
        args.bulk_encrypt is None):
        print('Nothing to do. Specify either --global-setup or --authority-setup or --keygen or --encrypt or --search or --bulk-encrypt.')
        farewell()

    key_path = args.key_path
    dir_create(key_path)

    lsabe_ma = LSABE_MA(key_path, MAX_KEYWORDS)

    if args.global_setup_flag:
        globalSetup(lsabe_ma, args.url)
    if args.authority_setup_flag:
        lsabe_auth = authoritySetup(args.url, MAX_KEYWORDS)

# SK generation
    if (args.keygen_flag):
        lsabe_auth = tryAuthorityLoadOrExit(key_path, MAX_KEYWORDS, args.authority_id)
        chekGIDorExit(args.GID)

        if len(args.attributes) == 0:
            print('--keygen flag is set but no security attributes are provided. '
                    'Security key generation requires at least one security attribute. --sec-attr "attribute-1" will be good enouph.')
            farewell()

        print('Executing "SecretKeyGen(MSK,i,PP,GID,ASK(i,j))→SK(i,GID)" ...')
        SK = lsabe_auth.SecretKeyGen(args.GID, args.attributes)
        try:
            sk_fname = key_path.joinpath(args.GID + '-authority-' + str(args.authority_id) + '.sk')   
            lsabe_auth.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            farewell()
        print('SK saved to ' + str(sk_fname))

    if (args.encrypt_flag or args.search_flag) and len(args.keywords) > MAX_KEYWORDS:
        print(str(len(args.keywords)) + ' keywords are provided. The maximum supported number of keywords is ' + str(MAX_KEYWORDS) + 
              ' If you want to change it, please modify MAX_KEYWORDS value in the source code') 
        farewell()

# Encrypt (file encryption and index generation)
    if (args.encrypt_flag):
        data_path = args.data_path
        dir_create(data_path)

        print('Executing "Encrypt  (M,(A,ρ),KW,PP,{APK(i,j)})→CT." ...')

        lsabe_auth = tryAuthorityLoadOrExit(key_path, MAX_KEYWORDS, args.authority_id)
       
        if len(args.keywords) == 0:
            print('--encrypt flag is set but no keywords are supplied.\n'
                    'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) → CT, where KW is a set of keywords.\n'
                    'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()

        print('Message: \'' + str(args.message) + '\'' )    
        print('Keywords: ' + str(args.keywords))    
        Encrypt(lsabe_auth, args.message, args.keywords, args.url, data_path, False, 0)

# Bulk encrypt messages    
    if args.bulk_encrypt is not None:
        data_path = args.data_path
        dir_create(data_path)

        lsabe_auth = tryAuthorityLoadOrExit(key_path, MAX_KEYWORDS, args.authority_id)
        print('Executing bulk encrypt from file ' + str(args.bulk_encrypt))
        try:
            file = open(args.bulk_encrypt, 'r')
            Lines = file.readlines()
        except:           
            print('Failed to read file ' + str(args.bulk_encrypt))
            farewell()

        nLine = 0
        nOk   = 0
        for line in Lines:
            nLine +=1
            data = line.strip().split(',')
            kwd = data[1:]
            if len(kwd) ==0:
                print('\nLine ' + str(nLine) +' -- no keywords, skipping.')
            else:    
                if Encrypt(lsabe_auth, data[0], data[1:], args.url, data_path, True, nLine):
                    nOk += 1
        
        print('\n' + str(nLine) + ' lines processed. ' + str(nOk) + ' messages loaded.')

# Search (trapdoor generation, search, transformation, decription)
    if (args.search_flag):
        lsabe_auth = tryAuthorityLoadOrExit(key_path, MAX_KEYWORDS, args.authority_id)
        chekGIDorExit(args.GID)

        if len(args.keywords) == 0:
            print('--search flag is set but no keywords are supplied.\n'
                    'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()

        data_path = args.data_path
        dir_create(data_path)

        sk_fname = key_path.joinpath(args.GID + '-authority-' + str(args.authority_id) + '.sk')   
        try:
            SK = lsabe_auth.deserialize__SK(sk_fname)
        except:
           print('Failed to load SK from ' + str(sk_fname))
           farewell()
        print('SK loaded from ' + str(sk_fname))

        print('Executing "Trapdoor ({SKi,GID},KW′,PP) → TKW′" ...')
        start = time.time()
        TD = lsabe_auth.TrapdoorGen(SK, args.GID, args.keywords) 
        trapdoor_gen_time = (time.time() - start) * 1000
        print('Executing "TransKeyGen({SKi,GID},z) → TKGID" ...')
        start = time.time()
        z =  lsabe_ma.z()
        TK = lsabe_auth.TransKeyGen(SK, z, args.GID)
        transkey_gen_time = (time.time() - start) * 1000

        if args.url is None:
            print('No URL provided, scanning local files at  ' + str(data_path) + ' ...')
            msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]
            for msg_file in msg_files:
                ct_fname = data_path.joinpath(msg_file)   
                CT = lsabe_auth.deserialize__CT(ct_fname)
                print('===== ' + msg_file + ' =====')
                print('Executing "Search(CT,TD) → True/False" ...')

                res = lsabe_auth.Search(CT, TD)
                print('Search algoritm returned "' + str(res) + '"')

                if res:
                    print('Executing "Transform (CT,TKGID) → CTout/⊥" ...')
                    CTout = lsabe_auth.Transform(CT, TK)   

                    print('Executing "Decrypt(z,CTout) → M" ...')
                    msg = lsabe_auth.Decrypt(z, CTout)
                    print('Message: \"' + msg + '\"' )

        else:
            print('Sending search request to: ' + str(args.url))
            try:    
                tds = io.BytesIO()
                lsabe_auth.serialize__TD(TD, tds, False)

                tks = io.BytesIO()
                lsabe_auth.serialize__TK(TK, tks, False)
                response = requests.get(args.url + "/search", 
                            files={'TD': tds.getvalue(), 'TK': tks.getvalue()})

                tds.close()
                tks.close()
            except:
                print('Failed to send search request to ' + str(args.url) + ' Please ensure that the server is running.')
                farewell()

            nmsg = 0
            if response.text is not None:
                if response.status_code==200:
                    try:
                        rsp = response.json()                    
                        nmsg= len(rsp['CTout'])     
                        t = str(nmsg) + ' partially decrypted messages received.'
                    except:
                        print('Failed to parse server response.')
                        farewell()
                else:    
                    t = response.text
            else:
                t = ""

            print('Server response ' + str(response.status_code) + '(' + response.reason + '). ' + t)

            if nmsg>0:
                print('Executing "Decrypt(z,CTout) → M" ...')
                decryption_time = 0
                for CTout in rsp['CTout']:
                    try:
                        CTout2 = lsabe_auth.deserialize__CTout(bytes(CTout, 'utf-8'), False)
                        tm = time.time()
                        msg = lsabe_auth.Decrypt(z, CTout2)
                        decryption_time += (time.time() - tm)
                        print('Message: \"' + msg + '\"' )
                    except:
                        print('Failed to decrypt a message.')
                decryption_time *= 1000
                print_evaluation_results(rsp, nmsg, trapdoor_gen_time, transkey_gen_time, decryption_time)

# Delete all message files
    if (args.clear_flag):
        if args.url is None:
            print('No url provided, clearing local message store')
            data_path = args.data_path
            dir_create(data_path)

            msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]
            print('Deleting ' + str(len(msg_files)) + ' message files')
            nDel = 0
            for msg_file in msg_files:
                try:
                    f = data_path.joinpath(msg_file)
                    os.remove(f)
                    print('.', end='')
                    nDel += 1
                except:
                    print('\nFailed to delete ' + str(f))
            print('\n' + str(nDel) + ' files deleted.')
        else:
            print('Sending clear-messages request to the server')
            try:
                response = requests.get(args.url + "/clear-messages")
            except:
                print('Failed to send clear-messages request to ' + str(args.url) + ' Please ensure that the server is running.')
                farewell()
            if response.text is not None:
                if (response.status_code==200):
                    try:
                        rsp = response.json()                    
                        nDel= str(rsp['nDel'])     
                        nErr= str(rsp['nErr'])      
                        t = 'Successfully deleted ' + nDel + ' messages'
                        if int(nErr)>0:
                            t = t + ', failed to delete ' + nErr + ' messages' 
                        else: 
                            t = t + '.'    
                    except:
                        print('Failed to parse server response.')
                        farewell()
                else:    
                    t = response.text
            else:
                t = ""
            print('Server response ' + str(response.status_code) + '(' + response.reason + '). ' + t)


# Encrypt routine. used both at bulk and single - message operations 
def Encrypt(auth, msg, kwd, url, data_path, bulk, nLine):
    bOk = True
    CT = auth.EncryptAndIndexGen( msg, kwd)
    if bulk:
        m = 'Line ' + str(nLine) + ':'
    else:
        m = ''
    if url is None:
        if not bulk:
            print('No URL provided, storing cyphertext locally')    
        ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        ct_fname = data_path.joinpath(ct_name + '.ciphertext')   
        try:
            auth.serialize__CT(CT, ct_fname)
        except:
            print(m + 'Failed to store ciphertext to ' + str(ct_fname))
            bOk = False
        if not bulk:
            print('Сiphertext stored to ' + str(ct_fname))
    else:
        if not bulk:
            print('Sending cyphertext to: ' + str(url))
        try:    
            bbuf = io.BytesIO()
            auth.serialize__CT(CT, bbuf, False)
            response = requests.post(url + "/store", files={'CT': bbuf.getvalue()})
            bbuf.close()
        except:
            print(m + 'Failed to send ciphertext to ' + str(url) + ' Please ensure that the server is running.')
            bOk = False
        if not bulk:
            print('Сiphertext sent to ' + str(url))
        if response.text is not None:
            t = response.text
        else:
            t = ""
        if not bulk or response.status_code != 200:
            print(m + 'Server response ' + str(response.status_code) + '(' + response.reason + '). ' + t)
        if response.status_code != 200:
            bOk = False
    if bulk:
        print('.', end='')
    return bOk

def print_evaluation_results(res, nmsg, trapdoor_gen_time, transkey_gen_time, decryption_time):
    print()
    print("Number of results: ", nmsg)
    print()
    print("Server - Overall searching time (ms): ", "{:,.2f}".format(res["total_time"]))
    print("Server - Searching time only (ms): ", "{:,.2f}".format(res["search_time"]))
    print("Server - Transform time only (ms): ", "{:,.2f}".format(res["transform_time"]))
    print("Server - Overhead time (ms): ", "{:,.2f}".format(res["total_time"]-res["search_time"]-res["transform_time"]))
    print()
    print("Server - Encrypted data sizes (before transformation):")
    print("Server - Results size (bytes)", "{:,.2f}".format(res["encrypted_size"]))
    print("Server - Results size (KB)", "{:,.2f}".format(res["encrypted_size"]/1024))
    print("Server - Results size (MB)", "{:,.2f}".format(res["encrypted_size"]/1024/1024))
    print()
    print("Server - Transformed data sizes:")
    print("Server - Transformed size (bytes)", "{:,.2f}".format(res["transformed_size"]))
    print("Server - Transformed size (KB)", "{:,.2f}".format(res["transformed_size"]/1024))
    print("Server - Transformed size (MB)", "{:,.2f}".format(res["transformed_size"]/1024/1024))
    print()
    print("Client - Trapdoor generation time (ms)", "{:,.2f}".format(trapdoor_gen_time))
    print("Client - Transformation key generation time (ms)", "{:,.2f}".format(transkey_gen_time))
    print("Client - Decryption time (ms)", "{:,.2f}".format(decryption_time))

