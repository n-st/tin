#!/usr/bin/env python3
# encoding: utf-8 (as per PEP 263)

from flask import Flask, Response, send_file, abort, redirect
from werkzeug.contrib.fixers import ProxyFix
import os
import magic

app = Flask(__name__)

# It's ok if we run into a KeyError here, since these variables are needed
# under all circumstances
app.config['TIN_DATAPATH'] = os.environ['TIN_DATAPATH']
app.config['TIN_INDEX'] = os.environ['TIN_INDEX']
app.config['TIN_REVERSEPROXY'] = os.environ['TIN_REVERSEPROXY']

if app.config['TIN_REVERSEPROXY']:
    app.wsgi_app = ProxyFix(app.wsgi_app)

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
    filename = parts[0].lower()
    filepath = os.path.join(app.config['TIN_DATAPATH'], filename)
    if os.path.isfile(filepath):
        try:
            with open(filepath, 'r') as f:
                # limit URL to reasonable length (as per RFC 7230, 3.1.1)
                line = f.readline(8 * 1024)
                # Make sure this was the only line in the file
                # This also involves checking the length limit, because we might
                # have stopped short of the end of the first line. If that's the
                # case, the line is so long we don't want to process it anyway.
                if len(line) < (8 * 1024) and f.readline(1) == '':
                    if line.startswith('http://') or line.startswith('https://'):
                        return redirect_to_url(line.strip())

        except:
            # Well that didn't work...
            # Fall back to serving it as a file instead.
            pass

        return send_mime_file(filepath)

    else:
        abort(404)

def send_mime_file(path):
    mimetype = mime.from_file(path)
    return send_file(path, mimetype=mimetype, as_attachment=False)

def redirect_to_url(url):
    return redirect(url, code=303)

if __name__ == "__main__":
    app.run()
