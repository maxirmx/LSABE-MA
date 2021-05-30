# ..... LSABE module frontend (aka command line and arguments processing) ......

import os
import argparse

import pathlib
import random
import string
import flask
import os, shutil
import requests
import json
from werkzeug.utils import secure_filename
from flask import request, jsonify
from .arguments import arguments_setup, dir_create
from .lsabe import LSABE
import time

def farewell():
        print('Exiting ... To get help please run python -m lsabe --help.')
        exit(-1)

def print_evaluation_results(res):
    print()
    print("Server - Number of results: ", res["num_of_results"])
    print("Server - Overall searching time (ms): ", res["overall_search_time_ms"])
    print("Server - Searching time only (ms): ", res["search_only_time_ms"])
    print("Server - Transform time only (ms): ", res["transform_only_time_ms"])
    print("Server - File I/O overhead time (ms): ", res["file_io_time_overhead_ms"])
    print()
    print("Server - Encrypted data sizes (before transformation):")
    print("Server - Results size (bytes)", res["encrypted_size_bytes"])
    print("Server - Results size (KB)", res["encrypted_size_kb"])
    print("Server - Results size (MB)", res["encrypted_size_mb"])
    print()
    print("Server - Transformed data sizes:")
    print("Server - Transformed size (bytes)", res["transformed_size_bytes"])
    print("Server - Transformed size (KB)", res["transformed_size_kb"])
    print("Server - Transformed size (MB)", res["transformed_size_mb"])

def decrypt_transformed_data(z,res,lsabe):
    print()

    decryption_time = 0
    for i in res:
        I = lsabe.group.deserialize(str.encode(i["I"]))
        CM = (i["CM"][0],i["CM"][1])
        TI = lsabe.group.deserialize(str.encode(i["TI"]))
        # print(I)

        CTout = (I,CM,TI)
        tm = time.time()
        msg = lsabe.Decrypt(z, CTout)
        decryption_time += time.time() - tm

    print("Client - Decryption time (ms)", "{:,.2f}".format(decryption_time))
    print()


def encrypt(args,key_path,lsabe):
    data_path = args.data_path
    dir_create(data_path)

    print('Executing "Encrypt(M,KW,(A,p),PP) -> CT" ...')

    if args.plaintext_file is None or not args.plaintext_file:
        if len(args.keywords) == 0:
            print('--encrypt flag is set but no keywords are supplied.\n'
                  'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) --> CT, where KW is a set of keywords.\n'
                  'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()

        if args.message is None or not args.message:
            print('--encrypt flag is set but no message to encrypt is supplied.\n'
                  'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) --> CT, where M is a message to encrypt.\n'
                  'Please provide it, using quotes if there is more then one word. --msg "A message" will be good enouph')
            farewell()

    try:
        sk_fname = key_path.joinpath('lsabe.sk')
        SK = lsabe.deserialize__SK(sk_fname)
    except:
        print('Failed to load SK from ' + str(sk_fname))
        farewell()
    print('SK loaded from ' + str(sk_fname))

    (K1, K2, K3, K4, K5) = SK

    # Encrypting the provided ciphertext and keywords
    if args.plaintext_file is None or not args.plaintext_file:
        ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        ct_fname = data_path.joinpath(ct_name + '.ciphertext')

        print('Message: \'' + str(args.message) + '\'')
        print('Keywords: ' + str(args.keywords))

        start = time.time()
        CT = lsabe.EncryptAndIndexGen(args.message, args.keywords)
        end = time.time() - start
        if args.evaluation == 'true':
            print("Encryption time (ms): ", "{:.2f}".format(end * 1000))

        try:
            lsabe.serialize__CT(CT, ct_fname)
        except:
            print('Failed to store ciphertext to ' + str(ct_fname))
            farewell()
        print('Сiphertext stored to ' + str(ct_fname))
    # Encrypt the provided file
    else:
        plain = pathlib.Path(__file__).parent.parent.joinpath('dataset').__str__() + "/" + args.plaintext_file
        with open(plain, 'r') as infile:
            start = time.time()
            for line in infile:
                ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
                ct_fname = data_path.joinpath(ct_name + '.ciphertext')
                line = line.replace("\n", "")
                msg = line.split(',')
                CT = lsabe.EncryptAndIndexGen(msg[0], msg[1:len(msg)])
                try:
                    lsabe.serialize__CT(CT, ct_fname)
                except:
                    print('Failed to store ciphertext to ' + str(ct_fname))
                    farewell()
        end = time.time() - start
        if args.evaluation == 'true':
            print("Encryption time (ms): ", "{:.2f}".format(end * 1000))

    # send data to the cloud
    if args.client_flag != '':
        print("Sending to the cloud: " + args.client_flag)

        files = []

        data_path = args.data_path
        dir_create(data_path)
        counter = 0
        msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]
        for msg_file in msg_files:
            ct_fname = data_path.joinpath(msg_file)
            files.append(('files', ((msg_file, open(ct_fname, 'rb'), 'text/plain'))))
            counter += 1
            if counter == 1000:
                test_response = requests.post(args.client_flag + "/send", files=files)
                counter = 0
                files.clear()
        if counter >0:
            test_response = requests.post(args.client_flag + "/send", files=files)
            counter = 0
            files.clear()



def clear_enc(args,key_path,lsabe):
    r = requests.get(url = args.client_flag + "/clear_encrypted")


def searchServer(args,json_data,key_path,lsabe):
    # Call the server to perform search
    T1 = lsabe.group.deserialize(str.encode(json_data["T1"]))
    T2 = lsabe.group.deserialize(str.encode(json_data["T2"]))
    T3 = lsabe.group.deserialize(str.encode(json_data["T3"]))
    T4 = lsabe.group.deserialize(str.encode(json_data["T4"]))
    tmp = []
    for i in range(10):
        tmp.append(lsabe.group.deserialize(str.encode(json_data["T5"][i])))
    T5 = tuple(tmp)
    TD = (T1,T2,T3,T4,T5)

    TK1 = lsabe.group.deserialize(str.encode(json_data["TK1"]))
    tmp = []
    for i in range(5):
        tmp.append(lsabe.group.deserialize(str.encode(json_data["TK2"][i])))
    TK2 = tuple(tmp)
    TK3 = lsabe.group.deserialize(str.encode(json_data["TK3"]))
    TK = (TK1,TK2,TK3)

    data_path = args.data_path
    dir_create(data_path)

    # print('Scanning ' + str(data_path) + ' ...')
    msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]

    overall_start = time.time()
    searching_time = 0
    transform_time = 0
    dec_time = 0
    counter = 0;
    files = []

    # search results
    transformed_data = []
    transformed_data_size = 0
    for msg_file in msg_files:
        ct_fname = data_path.joinpath(msg_file)
        CT = lsabe.deserialize__CT(ct_fname)

        # if args.evaluation != 'true':
        #     print('===== ' + msg_file + ' =====')
        #     print('Executing "Search(CT,TD) --> True/False" ...')

        tm = time.time()
        res = lsabe.Search(CT, TD)
        searching_time += time.time() - tm

        # if args.evaluation != 'true':
        #     print('Search algoritm returned "' + str(res) + '"')

        if res:
            counter += 1
            files.append(msg_file)

            tm = time.time()
            CTout = lsabe.Transform(CT, TK)
            transform_time += time.time() - tm

            # serialising data and adding it to the response
            aa = {}
            (I, CM, TI) = CTout
            aa["I"] = lsabe.group.serialize(I).decode("utf-8")
            aa["CM"] = CM
            aa["TI"] = lsabe.group.serialize(TI).decode("utf-8")
            transformed_data.append(aa)
            transformed_data_size += len(aa["I"]) + len(aa["CM"][0]) + len(aa["CM"][1]) + len(aa["TI"])

    overall_end = time.time() - overall_start

    evaluation_results = {}

    # if args.evaluation == 'true':
    print()
    evaluation_results["num_of_results"] = counter
    print("Number of results: ", counter)

    evaluation_results["overall_search_time_ms"] = "{:.2f}".format(overall_end * 1000)
    print("Overall searching time (ms): ", "{:.2f}".format(overall_end * 1000))

    evaluation_results["search_only_time_ms"] = "{:.2f}".format(searching_time * 1000)
    print("Searching time only (ms): ", "{:.2f}".format(searching_time * 1000))

    evaluation_results["transform_only_time_ms"] = "{:.2f}".format(transform_time * 1000)
    print("Transform time only (ms): ", "{:.2f}".format(transform_time * 1000))

    print()
    sizes = files_size(args, files)
    evaluation_results["encrypted_size_bytes"] = "{:,.2f}".format(sizes[0])
    print("Results size (bytes)", "{:,.2f}".format(sizes[0]))

    evaluation_results["encrypted_size_kb"] = "{:,.2f}".format(sizes[1])
    print("Results size (KB)", "{:,.2f}".format(sizes[1]))

    evaluation_results["encrypted_size_mb"] = "{:,.2f}".format(sizes[2])
    print("Results size (MB)", "{:,.2f}".format(sizes[2]))

    print()
    evaluation_results["transformed_size_bytes"] = "{:,.2f}".format(transformed_data_size)
    print("Results size (bytes)", "{:,.2f}".format(transformed_data_size))

    evaluation_results["transformed_size_kb"] = "{:,.2f}".format(transformed_data_size / 1024)
    print("Results size (KB)", "{:,.2f}".format(transformed_data_size))

    evaluation_results["transformed_size_mb"] = "{:,.2f}".format(transformed_data_size / 1024 / 1024)
    print("Results size (MB)", "{:,.2f}".format(transformed_data_size))

    evaluation_results["file_io_time_overhead_ms"] = "{:.2f}".format(
        (overall_end - (searching_time + transform_time + dec_time)) * 1000)
    print("File IO time -overhead- (ms): ",
          "{:.2f}".format((overall_end - (searching_time + transform_time + dec_time)) * 1000))

    response = {}
    response["transformed_data"] = transformed_data
    response["evaluation_results"] = evaluation_results
    return response


def search(args,key_path,lsabe):

    if len(args.keywords) == 0:
        print('--search flag is set but no keywords are supplied.\n'
              'Please provide at least one keyword. --kwd keyword will be good enouph')
        farewell()

    data_path = args.data_path
    dir_create(data_path)

    if args.client_flag:
        print("Performing search on the cloud")
        kwd = ','.join(args.keywords)
        print("====== Evaluation Results ======")
        try:
            sk_fname = key_path.joinpath('lsabe.sk')
            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            farewell()
        print('SK loaded from ' + str(sk_fname))

        start = time.time()
        TD = lsabe.TrapdoorGen(SK, args.keywords)
        end = time.time() - start
        if args.evaluation == 'true':
            print("Client - Trapdoor generation time (ms): ", "{:.2f}".format(end * 1000))
        tm = time.time()
        z = lsabe.z()
        TK = lsabe.TransKeyGen(SK, z)
        transkey_time = time.time() - tm
        if args.evaluation == 'true':
            print('Client - TransKeyGen(SK,z) --> TK execution time (ms)": ', "{:.2f}".format(transkey_time * 1000))

        # Converting trapdoor to JSON
        trapdoor = {}
        trapdoor["T1"] = lsabe.group.serialize(TD[0]).decode("utf-8")
        trapdoor["T2"] = lsabe.group.serialize(TD[1]).decode("utf-8")
        trapdoor["T3"] = lsabe.group.serialize(TD[2]).decode("utf-8")
        trapdoor["T4"] = lsabe.group.serialize(TD[3]).decode("utf-8")
        tt = []
        for i in range (10):
            tt.append(lsabe.group.serialize(TD[4][i]).decode("utf-8"))
        trapdoor["T5"] = tt
        trapdoor["TK1"] = lsabe.group.serialize(TK[0]).decode("utf-8")
        tt = []
        for i in range (5):
            tt.append(lsabe.group.serialize(TK[1][i]).decode("utf-8"))
        trapdoor["TK2"] = tt
        trapdoor["TK3"] = lsabe.group.serialize(TK[2]).decode("utf-8")

        # trapdoor["Z"] = lsabe.group.serialize(z).decode("utf-8")
        json_trapdoor = json.dumps(trapdoor)
        # print(json_trapdoor)

        r = requests.post(url=args.client_flag + "/search",json=json_trapdoor)
        # r = requests.get(url=args.client_flag + "/search?kwd=" + kwd + "&eval=true")
        # print(r.json())
        parsed = json.loads(r.content)
        # print(parsed["evaluation_results"])
        print_evaluation_results(parsed["evaluation_results"])
        decrypt_transformed_data(z,parsed["transformed_data"], lsabe)
        return

    print('Executing "Trapdoor(SK,KW\'",PP) --> TKW\'" ...')
    try:
        sk_fname = key_path.joinpath('lsabe.sk')
        SK = lsabe.deserialize__SK(sk_fname)
    except:
        print('Failed to load SK from ' + str(sk_fname))
        farewell()
    print('SK loaded from ' + str(sk_fname))

    start = time.time()
    TD = lsabe.TrapdoorGen(SK, args.keywords)
    end = time.time() - start
    if args.evaluation == 'true':
        print("Trapdoor generation time (ms): ", "{:.2f}".format(end * 1000))

    print('Scanning ' + str(data_path) + ' ...')
    msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]

    overall_start = time.time()
    searching_time = 0
    transkey_time = 0
    transform_time = 0
    dec_time = 0
    counter = 0;
    files = []

    # search results
    transformed_data = []
    transformed_data_size = 0
    for msg_file in msg_files:
        ct_fname = data_path.joinpath(msg_file)
        CT = lsabe.deserialize__CT(ct_fname)

        if args.evaluation != 'true':
            print('===== ' + msg_file + ' =====')
            print('Executing "Search(CT,TD) --> True/False" ...')

        tm = time.time()
        res = lsabe.Search(CT, TD)
        searching_time += time.time() - tm

        if args.evaluation != 'true':
            print('Search algoritm returned "' + str(res) + '"')

        if res:
            counter += 1
            files.append(msg_file)
            if args.evaluation != 'true':
                print('Executing "TransKeyGen(SK,z) --> TK" ...')
            tm = time.time()
            z = lsabe.z()
            TK = lsabe.TransKeyGen(SK, z)
            transkey_time += time.time() - tm

            if args.evaluation != 'true':
                print('Executing "Transform (CT,TK) --> CTout/⊥" ...')

            tm = time.time()
            CTout = lsabe.Transform(CT, TK)
            transform_time += time.time() - tm
            if args.evaluation != 'true':
                print('Executing "Decrypt(z,CTout) --> M" ...')

            aa = {}
            # serialising data and adding it to the response

            (I, CM, TI) = CTout
            aa["I"] = str(lsabe.group.serialize(I))
            aa["CM"] = CM
            aa["TI"] = str(lsabe.group.serialize(TI))
            #aa["Z"] = lsabe.group.serialize(z)
            transformed_data.append(aa)
            transformed_data_size += len(aa["I"]) + len(aa["CM"][0])+ len(aa["CM"][1])+ len(aa["TI"])# + len(aa["Z"])
            # tm = time.time()
            # msg = lsabe.Decrypt(z, CTout)
            # print('Message: \"' + msg + '\"')
            # dec_time += time.time() - tm

            # if args.evaluation != 'true':
            #     print('Message: \"' + msg + '\"')

    overall_end = time.time() - overall_start

    evaluation_results={}

    if args.evaluation == 'true':
        print()
        evaluation_results["num_of_results"] = counter
        print("Number of results: ", counter)

        evaluation_results["overall_search_time_ms"] = "{:.2f}".format(overall_end * 1000)
        print("Overall searching time (ms): ", "{:.2f}".format(overall_end * 1000))

        evaluation_results["keygen_time_ms"] = "{:.2f}".format(transkey_time * 1000)
        print("TransKey generation time only (ms): ", "{:.2f}".format(transkey_time * 1000))

        evaluation_results["search_only_time_ms"] = "{:.2f}".format(searching_time * 1000)
        print("Searching time only (ms): ", "{:.2f}".format(searching_time * 1000))

        evaluation_results["transform_only_time_ms"] = "{:.2f}".format(transform_time * 1000)
        print("Transform time only (ms): ", "{:.2f}".format(transform_time * 1000))

        # evaluation_results["decryption_only_time"] = "{:.2f}".format(dec_time * 1000)
        # print("Decryption time only (ms): ", "{:.2f}".format(dec_time * 1000))
        print()
        sizes = files_size(args,files)
        evaluation_results["encrypted_size_bytes"] = "{:,.2f}".format(sizes[0])
        print("Encrypted size (bytes)", "{:,.2f}".format(sizes[0]))

        evaluation_results["encrypted_size_kb"] = "{:,.2f}".format(sizes[1])
        print("Encrypted size (KB)", "{:,.2f}".format(sizes[1]))

        evaluation_results["encrypted_size_mb"] = "{:,.2f}".format(sizes[2])
        print("Encrypted size (MB)", "{:,.2f}".format(sizes[2]))

        print()
        evaluation_results["transformed_size_bytes"] = "{:,.2f}".format(transformed_data_size)
        print("Transformed size (bytes)", "{:,.2f}".format(transformed_data_size))

        evaluation_results["transformed_size_kb"] = "{:,.2f}".format(transformed_data_size/1024)
        print("Transformed size (KB)", "{:,.2f}".format(transformed_data_size))

        evaluation_results["transformed_size_mb"] = "{:,.2f}".format(transformed_data_size/1024/1024)
        print("Transformed size (MB)", "{:,.2f}".format(transformed_data_size))

        evaluation_results["file_io_time_overhead_ms"] = "{:.2f}".format((overall_end - (transkey_time + searching_time + transform_time + dec_time)) * 1000)
        print("File IO time -overhead- (ms): ",
              "{:.2f}".format((overall_end - (transkey_time + searching_time + transform_time + dec_time)) * 1000))

    response = {}
    response["transformed_data"] = transformed_data
    response["evaluation_results"] = evaluation_results
    # response = [
    #     ('transformed_data', transformed_data, 'application/json'),
    #     ('evaluation_results', evaluation_results, 'application/json'),
    # ]
    return response

def files_size(args,files=[]):
    # initialize the size
    total_size = 0
    path = args.data_path

    # path = pathlib.Path(__file__).parent.parent.joinpath('data').__str__() + "/"

    # use the walk() method to navigate through directory tree
    for dirpath, dirnames, filenames in os.walk(path):
        for i in files:
            # use join to concatenate all the components of path
            f = os.path.join(dirpath, i)

            # use getsize to generate size in bytes and add it to the total size
            total_size += os.path.getsize(f)
    return total_size, total_size/1024 , total_size/1024/1024

def startup():

    MAX_KEYWORDS = 10
    parser = arguments_setup(MAX_KEYWORDS)
    args = parser.parse_args()

    if (not args.init_flag and not args.keygen_flag and not args.encrypt_flag and not args.search_flag and not args.server_flag and not args.client_flag and not args.clear_encrypted):
        print('Nothing to do. Specify either --init or --keygen or --encrypt or --search.')
        farewell()

    key_path = args.key_path
    dir_create(key_path)

    lsabe = LSABE(key_path, MAX_KEYWORDS)
    # MSK and PP are requied always
# So we either generate them (SystemInit) or load from files (SystemLoad)
    if args.init_flag:
        print('Are you sure you want to generate new  master security key (MSK) and public properties (PP)? (yes or no)')
        answer = input().lower()
        if answer == "yes":
            print('Executing "Setup(k) --> (MSK,PP)" ...')
            try:
                start = time.time()
                lsabe.SystemInit()
                end = time.time() - start
                if args.evaluation == 'true':
                    print("System Init time (ms): ", "{:.2f}".format(end * 1000))
            except:
                print('Failed to store MSK and PP to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
                farewell()
            print('MSK and PP saved to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
        else:
            farewell()

    else:
        print('Loading master security key (MSK) and public properies (PP) from ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
        try:
            start = time.time()
            lsabe.SystemLoad()
            end = time.time() - start
            if args.evaluation == 'true':
                print("System load (ms): ", "{:.2f}".format(end * 1000))
        except:
            print('Failed to load MSK and PP')
            farewell()
        print('MSK and PP loaded succesfully')

    # SK and TK generation
    if (args.keygen_flag):
        print('Are you sure you want to generate new secret key (SK)? (yes or no)')
        answer = input().lower()
        if answer == "yes":
            print('Executing "SecretKeyGen(MSK,S,PP) --> SK" ...')
            sk_fname = key_path.joinpath('lsabe.sk')

            start = time.time()
            SK = lsabe.SecretKeyGen()
            end = time.time() - start
            if args.evaluation == 'true':
                print("Keygen time (ms): ", "{:.2f}".format(end * 1000))
            try:
                lsabe.serialize__SK(SK, sk_fname)
            except:
                print('Failed to store SK to ' + str(sk_fname))
                farewell()
            print('SK saved to ' + str(sk_fname))
        else:
            farewell()

    if (args.encrypt_flag or args.search_flag) and len(args.keywords) > MAX_KEYWORDS:
        print(str(len(args.keywords)) + ' keywords are provided. The maximum supported number of keywords is ' + str(MAX_KEYWORDS) +
              ' If you want to change it, please modify MAX_KEYWORDS value in the source code')
        farewell()

# Encrypt (file encryption and index generation)
    if (args.encrypt_flag):
        encrypt(args,key_path,lsabe)

    if (args.clear_encrypted):
        clear_enc(args,key_path,lsabe)

    # start REST api server
    if (args.server_flag):
        app = flask.Flask(__name__)
        app.config["DEBUG"] = True
        print("server should be running now")

        @app.route('/clear_encrypted', methods=['GET'])
        def delete_all_files():
            for filename in os.listdir("./data"):
                file_path = os.path.join("./data", filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print('Failed to delete %s. Reason: %s' % (file_path, e))

            for filename in os.listdir("./received_data"):
                file_path = os.path.join("./received_data", filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print('Failed to delete %s. Reason: %s' % (file_path, e))
            print("Files cleared")
            return "Files cleared"

        @app.route('/search', methods=['POST'])
        def search_api():
            args.data_path = pathlib.Path(__file__).parent.parent.joinpath('received_data')
            # print(request.get_json())
            # args.keywords =  request.args.get("kwd").split(',')
            # args.evaluation = request.args.get("eval")
            res = searchServer(args,json.loads(request.get_json()),key_path,lsabe)
            # if args.evaluation == "true":
            return jsonify(res)



        @app.route('/send', methods=['POST'])
        def send():
            uploaded_files = flask.request.files.getlist('files')
            #
            counter =0
            for file in uploaded_files:
                filename = secure_filename(file.filename)
                file.save(os.path.join("./received_data/", filename))
                counter+=1
            print("Encrypted files received: " + str(counter))
            return ""
        app.run()

    # Search (trapdoor generation, search, transformation, decription)
    if (args.search_flag):
        search(args,key_path,lsabe)