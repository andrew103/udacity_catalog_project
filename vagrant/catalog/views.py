from flask import Flask, jsonify, request, g, url_for, redirect
from models import Base, User, Category, Item
from sqlalchemy import create_engine
from functools import wraps

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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

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


@app.route('/login')
def login():
    return "This page is where a user can login or sign up"


@app.route('/')
@app.route('/catalog')
def showCatalog():
    return "This is the index page that will show all categories and the latest items added"


@app.route('/catalog/new')
@login_required
def newCategory():
    return "This page allows signed-in users to create new categories"


@app.route('/catalog/<string:cat_name/edit')
@login_required
def editCategory(cat_name):
    return "This page allows signed-in users to edit their categories"


@app.route('/catalog/<string:cat_name>/delete')
@login_required
def deleteCategory(cat_name):
    return "This page allows a signed-in user to delete a category they created"


@app.route('/catalog/<string:cat_name>')
@app.route('/catalog/<string:cat_name>/items')
def showCatItems(cat_name):
    return "This page will show all the items for a given category"


@app.route('/catalog/<string:cat_name>/new')
@login_required
def newItem(cat_name):
    return "This page allows a signed-in user to add a new item to a category"


@app.route('/catalog/<string:cat_name>/<string:item_name>/edit')
@login_required
def editItem(cat_name, item_name):
    return "This page allows a signed-in user to edit their items"


@app.route('/catalog/<string:cat_name>/<string:item_name>/delete')
@login_required
def deleteItem(cat_name, item_name):
    return "This page allows a signed-in user to delete their items"


@app.route('/catalog/<string:cat_name>/<string:item_name>')
@login_required
def showItemDescription(cat_name, item_name):
    return "This page will show the description of a specified item"



if __name__ == "__main__"
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host="0.0.0.0", port=8000)
