# ..... LSABE module frontend (aka command line and arguments processing) ......

import os
import io
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

def farewell():
        print('Exiting ... To get help please run python -m lsabe-ma --help.')
        exit(-1)

def tryAuthorityLoadOrExit(key_path, MAX_KEYWORDS, authority_id):
    if authority_id is None:
        print('Authority id is not specified. All LSABE-MA actions other then initialization are executed against specific aothority')
        farewell()

    print('Loading authority-' + str(authority_id) +' attributes and keys from ' + str(key_path))
    try:
        lsabe_auth = LSABE_AUTH(key_path, MAX_KEYWORDS, authority_id)
    except:
        print('Failed to initialize authority using master security key (MSK) and public properies (PP) at ' + str(key_path))
        farewell()

    try:
        lsabe_auth.AuthorityLoad()
    except:
        print('Failed to load authority-' + str(authority_id) +' attributes and keys.')
        farewell()
    print('authority-' + str(authority_id) + ' attributes and keys successfully loaded.')
    return lsabe_auth

def chekGIDorExit(GID):
    if GID is None or not GID:
        print('No user identifier is provided. This action can be executed against specific user only. '
              '--GID "user-1" will be good enouph.')
        farewell()

def startup():

    MAX_KEYWORDS = 10
    parser = arguments_setup(MAX_KEYWORDS)
    args = parser.parse_args()

    if (not args.global_setup_flag and not args.authority_setup_flag and not args.keygen_flag and not args.encrypt_flag and not args.search_flag):
        print('Nothing to do. Specify either --global-setup or --authority-setup or --keygen or --encrypt or --search.')
        farewell()

    key_path = args.key_path
    dir_create(key_path)

    lsabe_ma = LSABE_MA(key_path, MAX_KEYWORDS)

# MSK and PP are requied always
# So we either generate them (SystemInit) or load from files (SystemLoad)
    if args.global_setup_flag:
        print('Executing GlobalSetup (κ)→(PP,MSK) ...')
        try:
            lsabe_ma.GlobalSetup()
            response = requests.post(args.url + "/global-setup", files={'PP': lsabe_ma.pp_fname(), 'MSK': lsabe_ma.msk_fname()})
        except:
            print('Failed to store MSK and PP to ' + lsabe_ma.msk_fname +' and ' + lsabe_ma.pp_fname)
            farewell()
        print('MSK and PP saved to ' + lsabe_ma.msk_fname +' and ' + lsabe_ma.pp_fname)

    if args.authority_setup_flag:
        print('Executing AuthoritySetup (PP)→(APK(i,j),ASK(i,j)) ...')

        if args.authority_id is None:
            print('--authority-setup flag is set but authority id is not specified.')
            farewell()        
        if len(args.attributes) == 0:
            print('--authority-setup flag is set but no security attributes are provided. '
                    'Each authority shall manage at least one security attribute. --sec-attr attribute will be good enouph.')
            farewell()
        
        try:
            lsabe_auth = LSABE_AUTH(key_path, MAX_KEYWORDS, args.authority_id)
            print('Used master security key (MSK) and public properies (PP) at ' + str(key_path))
        except:
            print('Failed to initialize authority using master security key (MSK) and public properies (PP) at ' + str(key_path))
            farewell()

        try:
            lsabe_auth.AuthoritySetup(args.attributes)
            response = requests.post(args.url + "/authority-setup", 
                            files={ 'ASK': lsabe_auth.ask_fname(), 
                                    'ATT': lsabe_auth.att_fname(),  
                                    'APK': lsabe_auth.apk_fname()  })
        except:
            print('Failed to store authority-' + str(args.authority_id) + ' attributes and keys to ' + str(key_path))
            farewell()
        print('authority-' + str(args.authority_id) + ' attributes and keys saved to ' + str(key_path))

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
        CT = lsabe_auth.EncryptAndIndexGen( args.message, args.keywords)

        if args.url is None:
            print('No URL provided, storing cyphertext locally')    
            ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
            ct_fname = data_path.joinpath(ct_name + '.ciphertext')   
            try:
                lsabe_auth.serialize__CT(CT, ct_fname)
            except:
                print('Failed to store ciphertext to ' + str(ct_fname))
                farewell()
            print('Сiphertext stored to ' + str(ct_fname))
        else:
            print('Sending cyphertext to: ' + str(args.url))
            try:    
                bbuf = io.BytesIO()
                lsabe_auth.serialize__CT(CT, bbuf, False)
                response = requests.post(args.url + "/store", files={'CT': bbuf.getvalue()})
                bbuf.close()
            except:
                print('Failed to send ciphertext to ' + str(args.url) + ' Please ensure that the server is running.')
                farewell()
            print('Сiphertext sent to ' + str(args.url))
            if response.text is not None:
                t = response.text
            else:
                t = ""
            print('Server response ' + str(response.status_code) + '(' + response.reason + '). ' + t)

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
        TD = lsabe_auth.TrapdoorGen(SK, args.GID, args.keywords) 
# The code to serialize trapdoor ... (no need to do it with this frontend)
#        td_fname = key_path.joinpath(args.GID + '-authority-' + str(args.authority_id) + '.td')   
#        try:
#            lsabe_auth.serialize__TD(TD, td_fname)
#        except:
#            print('Failed to store trapdoor to ' + str(td_fname))
#            farewell()

        print('Executing "TransKeyGen({SKi,GID},z) → TKGID" ...')
        z =  lsabe_ma.z()
        TK = lsabe_auth.TransKeyGen(SK, z, args.GID)

# The code to serialize transformation key ... (no need to do it with this frontend)
#        tk_fname = out_path.joinpath(args.GID + '-authority-' + str(args.authority_id) + '.tk')   
#        try:
#            lsabe_auth.serialize__TK(TK, tk_fname)
#        except:
#            print('Failed to store TK to ' + str(tk_fname))
#            farewell()
#        print('TK saved to ' + str(tk_fname))

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
                if (response.status_code==200):
                    try:
                        rsp = response.json();                    
                        nmsg= len(rsp['CTout']);     
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
                for CTout in rsp['CTout']:
                    try:
                        CTout2 = lsabe_auth.deserialize__CTout(bytes(CTout, 'utf-8'), False)
                        msg = lsabe_auth.Decrypt(z, CTout2)
                        print('Message: \"' + msg + '\"' )
                    except:
                        print('Failed to decrypt a message.')

