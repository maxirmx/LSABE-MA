import os
import pathlib

from flask import Flask, request
from lsabe_ma.lsabe_ma import LSABE_MA
from lsabe_ma.lsabe_authority import LSABE_AUTH


def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    MAX_KEYWORDS = 10
    default_key_path = pathlib.Path(__file__).parent.parent.joinpath('keys')
    default_data_path = pathlib.Path(__file__).parent.parent.joinpath('data')
    default_authority_id = 1


    app.KGC  =  LSABE_MA(default_key_path, MAX_KEYWORDS)
    app.AUTH =  LSABE_AUTH(default_key_path, MAX_KEYWORDS, default_authority_id)

    # Heartbeat check
    @app.route('/heartbeat')
    def heartbeat():
        return 'Alive', 200

    @app.route('/global-setup', methods=['POST'])
    def globalSetup():
        return 'Alive', 200

    @app.route('/authority-setup', methods=['POST'])
    def authoritySetup():
        return 'Alive', 200

    @app.route('/store', methods=['POST'])
    def store():
        print(request.files)
        if 'CT' not in request.files:
            return "Cyphertext required", 422
        else:
            x = request.files['CT']
            print(x.getvalue())
        return 'Cyphertext stored', 200

    @app.route('/search', methods=['GET'])
    def authoritySetup():
        return 'Alive', 200

    return app