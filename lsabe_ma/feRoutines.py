# ..... Frontend support routines ......

import requests

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

def globalSetup(lsabe_ma, args):
    print('Executing GlobalSetup (κ)→(PP,MSK) ...')
    try:
        lsabe_ma.GlobalSetup()
    except:
        print('Failed to store MSK and PP to ' + lsabe_ma.msk_fname +' and ' + lsabe_ma.pp_fname)
        farewell()
    print('MSK and PP saved to ' + lsabe_ma.msk_fname +' and ' + lsabe_ma.pp_fname)

    if args.url is not None:
        try:
            response = requests.post(args.url + "/global-setup", files={'PP': lsabe_ma.pp_fname(), 'MSK': lsabe_ma.msk_fname()})
            if (response.status_code==200):
                print('MSK and PP succesfully updated at ' + args.url)
            else:
                print('Failed to update MSK and PP at ' + args.url)
        except:
            print('Failed to send MSK and PP to ' + args.url)

def authoritySetup(args, MAX_KEYWORDS):
    print('Executing AuthoritySetup (PP)→(APK(i,j),ASK(i,j)) ...')

    if args.authority_id is None:
        print('--authority-setup flag is set but authority id is not specified.')
        farewell()        
    if len(args.attributes) == 0:
        print('--authority-setup flag is set but no security attributes are provided. '
                    'Each authority shall manage at least one security attribute. --sec-attr attribute will be good enouph.')
        farewell()
        
    try:
        lsabe_auth = LSABE_AUTH(args.key_path, MAX_KEYWORDS, args.authority_id)
        print('Used master security key (MSK) and public properies (PP) at ' + str(args.key_path))
    except:
        print('Failed to initialize authority using master security key (MSK) and public properies (PP) at ' + str(args.key_path))
        farewell()

    try:
        lsabe_auth.AuthoritySetup(args.attributes)
    except:
        print('Failed to store authority-' + str(args.authority_id) + ' attributes and keys to ' + str(args.key_path))
        farewell()
    print('authority-' + str(args.authority_id) + ' attributes and keys saved to ' + str(args.key_path))
 
    if args.url is not None:
        try:
            response = requests.post(args.url + "/authority-setup", 
                            files={ 'ASK': lsabe_auth.ask_fname(), 
                                    'ATT': lsabe_auth.att_fname(),  
                                    'APK': lsabe_auth.apk_fname()  })
            if (response.status_code==200):
                print('authority-' + str(args.authority_id) + ' atributes succesfully updated at ' + args.url)
            else:
                print('Failed to update authority-' + str(args.authority_id) + ' atributes at ' + args.url)
        except:
            print('Failed to send authority-' + str(args.authority_id) + ' atributes to ' + args.url)

    return lsabe_auth