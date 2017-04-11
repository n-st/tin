#!/usr/bin/env python3
# encoding: utf-8 (as per PEP 263)

from flask import Flask, Response, send_file, abort
from werkzeug.contrib.fixers import ProxyFix
import os
import magic

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# It's ok if we run into a KeyError here, since these variables are needed
# under all circumstances
app.config['TIN_DATAPATH'] = os.environ['TIN_DATAPATH']
app.config['TIN_INDEX'] = os.environ['TIN_INDEX']

mime = magic.Magic(mime=True)

@app.route('/')
def root():
    filepath = app.config['TIN_INDEX']
    if os.path.isfile(filepath):
        return send_mime_file(filepath)
    else:
        abort(404)

@app.route('/<path>')
def serve_file(path):
    parts = path.split('.', 2)
    filename = parts[0]
    filepath = os.path.join(app.config['TIN_DATAPATH'], filename)
    if os.path.isfile(filepath):
        return send_mime_file(filepath)
    else:
        abort(404)

def send_mime_file(path):
    mimetype = mime.from_file(path)
    return send_file(path, mimetype=mimetype, as_attachment=False)

if __name__ == "__main__":
    app.run()
