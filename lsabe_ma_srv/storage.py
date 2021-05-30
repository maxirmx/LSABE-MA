import os
import io
import pathlib
import random
import string

from flask import Flask, request, jsonify
from lsabe_ma.lsabe_ma import LSABE_MA
from lsabe_ma.lsabe_authority import LSABE_AUTH


def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    MAX_KEYWORDS = 10
    default_authority_id = 1
    key_path = pathlib.Path(__file__).parent.parent.joinpath('keys')
    data_path = pathlib.Path(__file__).parent.parent.joinpath('storage')


    KGC  =  LSABE_MA(key_path, MAX_KEYWORDS)
    AUTH =  LSABE_AUTH(key_path, MAX_KEYWORDS, default_authority_id)

    dir_create(data_path)
    data = set()


    try:
        msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]
        numfiles = 0
        for msg_file in msg_files:
            ct_fname = data_path.joinpath(msg_file)
            f = open(ct_fname, 'rb')
            d = f.read()
            data.add(d) 
            f.close 
            numfiles +=1 

        print(str(numfiles) + ' encrypted messages loaded')
    except:
        print('Failed to load messages from file storage')
        exit (-1)



    # ------------------------------------------------
    # Heartbeat 
    @app.route('/heartbeat')
    def heartbeat():
        return 'Alive', 200

    # ------------------------------------------------
    # Update global setup parameters
    @app.route('/global-setup', methods=['POST'])
    def globalSetup():
        if 'MSK' not in request.files or 'PP' not in request.files:
            return 'Master key (MSK) and public parameter (PP) are required', 422
        else:
            msk = request.files['MSK']
            pp  = request.files['PP']
            try:
                msk.save(app.KGC.msk_file())
                pp.save(app.KGC.msk_file())
            except:
                return 'Failed to save MSK and PP',500
            try:    
                KGC  =  LSABE_MA(key_path, MAX_KEYWORDS)
                AUTH =  LSABE_AUTH(key_path, MAX_KEYWORDS, default_authority_id)
            except:
                return 'Failed to apply MSK and PP',500
        return 'Global setup succesfully updated', 200

    # ------------------------------------------------
    # Update authority setup parameters
    @app.route('/authority-setup', methods=['POST'])
    @app.route('/authority-setup/<authority_id>', methods=['POST'])
    def authoritySetup(authority_id=None):
        if authority_id is None:
            authority_id = default_authority_id

        if 'ASK' not in request.files or 'ATT' not in request.files or 'APK' not in request.files:
            return 'Authority secret key (ASK), public key (APK) and attributes (ATT) are required', 422
        else:
            ask = request.files['ASK']
            apk = request.files['APK']
            att = request.files['ATT']
            try:
                ask.save(app.AUTH.ask_file())
                apk.save(app.AUTH.apk_file())
                att.save(app.AUTH.att_file())
            except:
                return 'Failed to save ASK, APK and ATT',500
            try:    
                AUTH =  LSABE_AUTH(key_path, MAX_KEYWORDS, default_authority_id)
            except:
                return 'Failed to apply ASK, APK and ATT',500
        return 'Authority setup succesfully updated', 200

    # ------------------------------------------------
    # Store cyfertext
    @app.route('/store', methods=['POST'])
    def store():
        if 'CT' not in request.files:
            return "Cyphertext required", 422
        else:
            CT = request.files['CT'].stream.read()
            data.add(CT)
            ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
            ct_fname = data_path.joinpath(ct_name + '.ciphertext')   
            f = open(ct_fname, 'wb')
            f.write(CT)
            f.close()

        return 'Cyphertext stored', 200

    # ------------------------------------------------
    # Search cyfertext (apply trapdoor, etc )
    @app.route('/search', methods=['GET'])
    def search():
        res = False
        rsp = []
        if 'TD' not in request.files:
            return "Trapdoor is required", 422
        if 'TK' not in request.files:
            return "Transformation key is required", 422
        td = request.files['TD'].stream.read()
        tk = request.files['TK'].stream.read()
        for ct in data:
            ctds = AUTH.deserialize__CT(ct, False)
            r = AUTH.Search(ctds, AUTH.deserialize__TD(td, False))
            res = res or r
            if r:
                CTout = AUTH.Transform(ctds, AUTH.deserialize__TK(tk, False))
                cts = io.BytesIO()
                AUTH.serialize__CTout(CTout, cts, False)
                rsp.append(cts.getvalue().decode('ascii'))

        if res:
            return jsonify({'CTout': rsp}), 200
            
        return 'Message was not found.', 404

    return app

def dir_create(pth):
    try:
        pth.mkdir(mode=0o777, parents=True, exist_ok=True)
    except:
        if pth.Exists() and not pth.is_dir():
            print(str(pth) + ' exists and is not a directory')
        else:
            print('Could not create ' + str(pth))
        print('Exiting ...')
        exit(-1)
