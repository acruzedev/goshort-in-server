from flask import *
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import sessionmaker
import random
import string
import os
import re
import urllib
import hashlib
from sqlalchemy.sql import func
from flask_cors import CORS, cross_origin


regex = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

alias_regex = re.compile('^[A-Za-z0-9\-\_]+$')

app = Flask(__name__)
project_dir = os.path.dirname(os.path.abspath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = "Your connection string is here."
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
HASH_LENGTH = 6

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

# modal
class CpmbUrl(db.Model):
    __tablename__ = 'cpmburl'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    url = db.Column(db.String())
    md5 = db.Column(db.String())
    hashd = db.Column(db.String())
    visited = db.Column(db.Integer)
    is_private = db.Column(db.Integer)
    is_pinmyblogs_url = db.Column(db.Integer)

    def __init__(self, name, url, md5, visited, hashd):
        self.name = name
        self.url = url
        self.md5 = md5
        self.visited = visited
        self.hashd = hashd
        self.is_private = 0
        self.is_pinmyblogs_url = 0

    def __repr__(self):
        return self.name


def engine(url, alias=None):
    print("hello")
    if alias == None or alias == "":
        hash = generate_new_random(length=HASH_LENGTH) if url else ""
        if hash is not "":
            md5 = hashlib.md5(url.encode()).hexdigest()
            result = db.session.query(CpmbUrl).filter(CpmbUrl.md5 == md5)
            r = [row for row in result if row.md5 == md5]

            if not r:
                me = CpmbUrl(name="", url=url, md5=md5, hashd=hash, visited=0)
                db.session.add(me)
                db.session.commit()
            else:
                hash = r[0].hashd
            return ({
                "status": "success",
                "message": "Short Url generated.",
                "short_url": "goshort.in/{0}".format(hash),
                "hash": hash,
                "ori_url": url
            })
    else:
        result = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == alias)
        r = [row for row in result if row.hashd == alias]
        if len(r) == 0:
            md5 = hashlib.md5(url.encode()).hexdigest()
            me = CpmbUrl(name="", url=url, md5=md5, hashd=alias, visited=0)
            db.session.add(me)
            db.session.commit()
            return ({
                "status": "success",
                "message": "Short Url generated.",
                "short_url": "goshort.in/{0}".format(alias),
                "hash": alias,
                "ori_url": url
            })

        else:
            return {
                "status": "error",
                "message": "Alias is already used.",
                "ori_url": url,
                "short_url": "goshort.in/{0}".format(alias),
                "alias": alias,

            }


# apis

@app.route("/api/v1/create", methods=["GET", 'POST'])
@cross_origin()
def api_create():
    try:
        url = request.args.get('url')
        alias = request.args.get('alias')
        message = ""

        if url is None or url is "":
            status = "empty" if url is "" else "missing"
            message = "Request param url is " + status + "."

        elif re.match(regex, url) is None:
            message = "Invalid weblink in request param url."

        else:
            alias_empty_none = bool(alias is not None and alias is not "")

            if alias_empty_none:
                alias_status = re.match(alias_regex, alias)
                if alias_status is not None:
                    return jsonify(engine(url, alias=alias))
                elif alias_status is None:
                    message += "Request param alias may contain letters, numbers, and dashes."
            elif alias is None or alias is "":
                return jsonify(engine(url, alias=None))

        return jsonify({"status": "error", "message": message})
    except  Exception as e:
        print(e)
        return jsonify({"status": "error", "message": message})


@app.route("/api/v1/track", methods=["GET", 'POST'])
# @cross_origin()
def api_track():
    hashd = request.args.get('hash') or ""
    if hashd is not None and hashd is not "":
        result = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == hashd)
        r = [row for row in result]
        # print(r)
        if not r:
            return jsonify({
                "status": "error",
                "message": "Url not found.",
                "hash": hashd
            })
        else:
            hash = r[0].hashd
            count = r[0].visited
            print(r)
            return jsonify({
                "status": "success",
                "message": "Url clicked {0} times.".format(count),
                "short_url": "goshort.in/{0}".format(hash),
                "hash": hash,
                "click_count": count,
                "ori_url": r[0].url
            })
            render_template('track.html', count=r[0].visited, hashd=hash, url=r[0].url)
    return jsonify({
        "status": "error",
        "message": "Request parameter(s) [hash] is blank or wrong."
    })


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])


@app.route("/term_of_use", methods=["GET", 'POST'])
def terms_of_use():
    return render_template('termsofuse.html')


@app.route("/disclaimer", methods=["GET", 'POST'])
def disclaimer():
    return render_template('disclaimer.html')


@app.route("/contact", methods=["GET", 'POST'])
def contact():
    return redirect("http://pinmyblogs.com/support")


@app.route("/privacy", methods=["GET", 'POST'])
def privacy():
    return render_template('privacy.html')


@app.route("/", methods=["GET", 'POST'])
def index():
    return render_template('index.html')


@app.route("/create", methods=["GET", 'POST'])
def create():
    url = request.args.get('url') or ""
    status = True if url == "" else True
    hash = ""
    if url is not None and url is not "":
        sgt = re.match(regex, url) is not None
        status = True if sgt == True else False
        hash = generate_new_random(length=HASH_LENGTH) if status else ""
        if hash is not "":
            md5 = hashlib.md5(url.encode())
            md5 = md5.hexdigest()
            result = db.session.query(CpmbUrl).filter(CpmbUrl.md5 == md5)
            r = [row for row in result if row.md5 == md5]

            if not r:
                me = CpmbUrl(name="", url=url, md5=md5, hashd=hash, visited=0)
                db.session.add(me)
                db.session.commit()
            else:
                hash = r[0].hashd
    return render_template('create.html', url=url, status=status, hash=hash)


@app.route("/track", methods=["GET", 'POST'])
def track():
    hashd = request.args.get('t') or ""
    if hashd is not None and hashd is not "":
        print(hashd)
        result = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == hashd)
        print(result)
        r = [row for row in result]
        print(r)
        if not r:
            return render_template('track.html', dummy=hashd)
        else:
            hash = r[0].hashd
            print(r)
            render_template('track.html', count=r[0].visited, hashd=hash, url=r[0].url)
    return render_template('track.html')


@app.route("/<path:dummy>", methods=["GET", 'POST'])
def index1(dummy=None):
    if dummy is not None:
        result = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == dummy.strip()).all()
        r = [row.url for row in result if row.hashd == dummy]
        if r:
            a = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == dummy.strip()).update(
                {'visited': CpmbUrl.visited + 1})
            db.session.commit()
            return redirect(r[0])
        else:
            return render_template('index.html', dummy=dummy)
    return redirect(url_for("index"))


# helper functions
def generate_new_random(length=6, chars=string.ascii_letters + string.digits):
    gen = ''.join(random.choice(chars) for _ in range(length))
    result = db.session.query(CpmbUrl).filter(CpmbUrl.hashd == gen)
    r = [row.md5 for row in result if row.md5 == gen]
    return generate_new_random() if r else gen


if __name__ == "__main__":
    app.run(debug=False)
    app.run(host='0.0.0.0')
