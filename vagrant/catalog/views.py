from flask import Flask, jsonify, request, g, url_for, redirect, render_template
from models import Base, User, Category, Item
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from functools import wraps

import flask_login
from flask_login import LoginManager
login = flask_login.login_user
logout = flask_login.logout_user

from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

from redis import Redis
redis = Redis()

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


# ============ BEGIN RATE LIMITING CODE ===================
class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)


def on_over_limit(limit):
    return (jsonify({'data':'You hit the rate limit','error':'429'}),429)


def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator


@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response

# ================= END RATE LIMITING CODE ====================

# ================= BEGIN LOGIN REQUIREMENT CODE ==============

@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(name = username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

# ================== END LOGIN REQUIREMENT CODE ===============

@app.route('/catalog/json')
def jsonCatalog():
    return "This page is where a json file of the catalog can be obtained"


@app.route('/catalog/<string:cat_name>/json')
@app.route('/catalog/<string:cat_name>/items/json')
def jsonCatItems(cat_name):
    return "This page is where a json file of the category items can be obtained"


@app.route('/catalog/<string:cat_name>/<string:item_name>/json')
def jsonItem(cat_name, item_name):
    return "This page is where a json file of an item and its attributes can be obtained"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['emailinput']
        password = request.form['passinput']
        try:
            user = session.query(User).filter_by(email=email).one()
            if user.verify_password(password):
                login(user)
                flash("You have logged in successfully" + user.name)
                return redirect(url_for('showCatalog'))
            else:
                flash("You have entered an incorrect password. Please try again")
                return redirect(url_for('login'))

        except:
            flash("User does not exist. Please create an account")
            return redirect(url_for('signup'))
    else:
        return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form['nameinput']
        email = request.form['emailinput']
        password = request.form['passinput']
        newUser = User(name=user, email=email)
        newUser.hash_password(password)

        session.add(newUser)
        session.commit()
        return redirect(url_for('login.html'))
    else:
        return render_template('signup.html')


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category).all()
    latest = session.query(Item).all()[-1:-10]
    return render_template('catalog.html', categories=categories, latest=latest)


@app.route('/catalog/new', methods=['GET', 'POST'])
# @auth.login_required
def newCategory():
    categories = session.query(Category).all()
    if request.method == 'POST':
        name = request.form['cat_name']
        # user = flask_login.current_user

        newCat = Category(name=name)#, user_id=user.id)
        session.add(newCat)
        session.commit()

        return redirect(url_for('showCatItems', cat_name=name))
    else:
        return render_template('newcategory.html', categories=categories)


@app.route('/catalog/<string:cat_name>/edit', methods=['GET', 'POST'])
# @auth.login_required
def editCategory(cat_name):
    categories = session.query(Category).all()
    if request.method == 'POST':
        name = request.form['cat_name']

        editedCat = session.query(Category).filter_by(name=cat_name).one()
        editedCat.name = name

        return redirect(url_for('showCatItems', cat_name=name))
    else:
        return render_template('editcategory.html', categories=categories, cat_name=cat_name)


@app.route('/catalog/<string:cat_name>/delete', methods=['GET', 'POST'])
# @auth.login_required
def deleteCategory(cat_name):
    categories = session.query(Category).all()
    if request.method == 'POST':
        currentCat = session.query(Category).filter_by(name=cat_name).one()
        session.delete(currentCat)
        session.commit()

        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletecategory.html', categories=categories, cat_name=cat_name)


@app.route('/catalog/<string:cat_name>')
@app.route('/catalog/<string:cat_name>/items')
def showCatItems(cat_name):
    categories = session.query(Category).all()
    currentCat = session.query(Category).filter_by(name=cat_name).one()
    items = session.query(Item).filter_by(cat_id=currentCat.id).all()
    return render_template('showitems.html', categories=categories, cat_name=cat_name, items=items)


@app.route('/catalog/<string:cat_name>/new', methods=['GET', 'POST'])
# @auth.login_required
def newItem(cat_name):
    categories = session.query(Category).all()
    if request.method == 'POST':
        name = request.form['item_name']
        description = request.form['item_description']
        cat = session.query(Category).filter_by(name=cat_name).one()
        # user = flask_login.current_user

        createdItem = Item(name=name, description=description, cat_id=cat.id)#user_id=user.id,
        session.add(createdItem)
        session.commit()

        return redirect(url_for('showItemDescription', cat_name=cat_name, item_name=name))
    else:
        return render_template('newitem.html', categories=categories, cat_name=cat_name)


@app.route('/catalog/<string:cat_name>/<string:item_name>/edit', methods=['GET', 'POST'])
# @auth.login_required
def editItem(cat_name, item_name):
    categories = session.query(Category).all()
    if request.method == 'POST':
        name = request.form['item_name']
        description = request.form['item_description']

        editedItem = session.query(Item).filter_by(name=item_name).one()
        editedItem.name = name
        editedItem.description = description

        return redirect(url_for('showItemDescription', cat_name=cat_name, item_name=name))
    else:
        return render_template('edititem.html', categories=categories, cat_name=cat_name, item_name=item_name)


@app.route('/catalog/<string:cat_name>/<string:item_name>/delete', methods=['GET', 'POST'])
# @auth.login_required
def deleteItem(cat_name, item_name):
    categories = session.query(Category).all()
    if request.method == 'POST':
        currentItem = session.query(Item).filter_by(name=item_name).one()
        session.delete(currentItem)
        session.commit()

        return redirect(url_for('showCatItems', cat_name=cat_name))
    else:
        return render_template('deleteitem.html', categories=categories, cat_name=cat_name, item_name=item_name)


@app.route('/catalog/<string:cat_name>/<string:item_name>')
# @auth.login_required
def showItemDescription(cat_name, item_name):
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('showitemdetail.html', categories=categories, cat_name=cat_name, item=item)



if __name__ == "__main__":
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host="0.0.0.0", port=8000)
