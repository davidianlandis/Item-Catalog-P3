from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
app = Flask(__name__)

# xml - https://github.com/quandyfactory/dicttoxml - Ryan McGreal
import dicttoxml

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User, Nonce

# NEW IMPORTS FOR OAUTH
from flask import session as login_session  # as [[name]] since session is being used below for our database setup.  this session variable acts as a dict to store data for the user
import random, string

# IMPORTS FOR gconnect (google oauth) function
from oauth2client.client import flow_from_clientsecrets  # creates a flow object to store secret ids to json file
from oauth2client.client import FlowExchangeError # in case we encounter an error trying to use authorization code to get access token - we can catch it
import httplib2 # client library 
import json # serialize python objects
from flask import make_response # converts the return value from a function to an object we can send
import requests  #  http library similar to urllib2

import datetime



#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()



"""
NONCE METHODS
"""
# Create/ Store/ Return a nonce - when a request for a nonce is made, create one, and store it along with the session state provided.
def getNonce():
    nonce = ''.join( random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in xrange(512))
    newNonce = Nonce(state=login_session['state'],nonce=nonce)
    session.add(newNonce)
    session.commit()
    return nonce
    

# Verify that nonce - using both the session state variable that was used to create it, and the nonce received from to server from client-side form.
def verifyNonce(state, nonce):
    # if bad, return false
    if session.query(Nonce).filter(Nonce.state == state, Nonce.nonce == nonce).count()<1:
        return False
    # if good, delete it and return true
    else:
        n = session.query(Nonce).filter(Nonce.state == state, Nonce.nonce == nonce).one()
        session.delete(n)
        session.commit()
        return True
"""
END NONCE
"""

    
    
    
# Show Login Screen
@app.route('/login/')
def showLogin():
    # random 64 character state variable
    state = ''.join( random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in xrange(64))
    login_session['state'] = state
    return render_template('login.html', state = state)
    


""" BEGIN GOOGLE AUTH SECTION """
# downloaded JSON from google OAuth for client secrets
CLIENT_ID = json.loads(open('google_secrets.json','r').read())['web']['client_id']

# server side google oauth function
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # does the state session token match?
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter ('+request.args.get('state')+')',401))
        response.headers['Content-Type'] = 'application/json'
        return response
        
    code = request.data # one-time-use-code from our ajax call from login.html 
    try:
        #upgrade the authorization code into a credentials object - which would contain the access token for our server
        oauth_flow = flow_from_clientsecrets('google_secrets.json', scope='') # create the oauth flow object and add our secret key to it
        oauth_flow.redirect_uri = 'postmessage' # specify one-time-code flow
        credentials = oauth_flow.step2_exchange(code) # to the exchange of the code for the object
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
        
    #####################################
    # Check for valid access token by getting the info for it
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])  # JSON get request containing that url
    
    # check for an error with the access_token
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
        
    # Now check for the CORRECT ACCESS TOKEN
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id: # is the ID from the exchange the same id from our JSON GET check of the token?
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
        
    # Now same kind of check for the Client ID (who our app is)
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID doesn't match app's ID."), 401)
        print "Token's client ID does not match app's ID."
        response.headers['Content-Type'] = 'application/json'
        return response
    #####################################    

    
    
    # Check if the user is already logged in - return a success without resetting all the session variables
    stored_credentials = login_session.get('credentials')
        #stored_credentials = login_session['credentials']
    stored_gplus_id = login_session.get('gplus_id')
        #stored_gplus_id = login_session['gplus_id']
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    
    
    # Store the valid access token info
    login_session['provider'] = 'google'
    #return "so far okay"
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    
    # Get some more user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token' : credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    
    # Store the ones we need
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    
    # Does this user already exist?
    user_id = getUserID(login_session['email'])
    if(user_id is None):
        login_session['user_id'] = createUser(login_session)
    login_session['user_id'] = user_id
    
    
    
    # Did this work?
    output = ''
    output += ' <h1>Welcome, ' + login_session['username'] + '!</h1>'
    output += '<img src="' + login_session['picture'] + '" style="width:300px; height:300px;border-radius:150px;-webkit-border-radius:150px;-moz-border-radius:150px;" />'
    flash("You are now logged in as %s" % login_session['username'])
    return output


# DISCONNECT - Revoke current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials.access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # token used to revoke was invalid...?
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

""" END GOOGLE AUTH SECTION """


""" BEGIN FACEBOOK AUTH SECTION """

# server side facebook oauth function
@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    access_token = request.data

    # Exchange this short-lived token for long-lived server-side token with
    #       GET /oauth/access_token?grant_type=fb_exchange_token&client_id={app-id}&client_secret={app-secret}&fb_exchange_token={short-lived-token}
    
    app_id = json.loads(open('fb_secrets.json','r').read())['web']['app_id']
    app_secret = json.loads(open('fb_secrets.json','r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
    
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    
    # Use token to get user info from APIs
    userinfo_url = "https://graph.facebook.com/v2.3/me"
    # strip expire taf from access token
    token = result.split("&")[0]
    
    url = 'https://graph.facebook.com/v2.3/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    #
    #
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    
    # Now get the picture with another api call
    url = 'https://graph.facebook.com/v2.3/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]
    
    # Does this user already exist?
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    
    output = ''
    output += ' <h1>Welcome, ' + login_session['username'] + '!</h1>'
    output += '<img src="' + login_session['picture'] + '" style="width:300px; height:300px;border-radius:150px;-webkit-border-radius:150px;-moz-border-radius:150px;" />'
    flash("You are now logged in as %s" % login_session['username'])
    return output

# Facebook logout
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return result

""" END FACEBOOK AUTH SECTION """


    
# Generic Disconnect
@app.route('/disconnect/')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        
        flash("You have successfully logged out.")
        return redirect(url_for('catalog'))
    else:
        flash("You do not appear to be logged in...")
        return redirect(url_for('catalog'))


        
        
"""
JSON API
"""
# Get all the items - grouped into categories
@app.route('/catalog/JSON/')
def catalogJSON():
    categories = session.query(Category).order_by(Category.name.asc()).all()
    sCats = []
    for c in categories:
        cat = c.serialize
        items = session.query(Item).filter(Item.category_id == c.id).all()
        sItems = []
        for i in items:
            sItems.append(i.serialize)
        cat['items'] = sItems
        sCats.append(cat)
    return jsonify(categories = [sCats])
        
# Get all the categories
@app.route('/categories/JSON/')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories = [i.serialize for i in categories])

# Get all the items for a specific category
@app.route('/category/<int:category_id>/JSON/')
def categoryItemsJSON(category_id):
    items = session.query(Item).filter(Item.category_id == category_id).all()
    return jsonify(items = [i.serialize for i in items])


"""
XML API
"""
# Get all the items - grouped into categories
@app.route('/catalog/XML/')
def catalogXML():
    categories = session.query(Category).order_by(Category.name.asc()).all()
    sCats = []
    for c in categories:
        cat = c.serialize
        items = session.query(Item).filter(Item.category_id == c.id).all()
        sItems = []
        for i in items:
            sItems.append(i.serialize)
        cat['items'] = sItems
        sCats.append(cat)
    #return jsonify(categories = [sCats])
    return dicttoxml.dicttoxml({"categories" : [sCats]})
    
# Get all the categories
@app.route('/categories/XML/')
def categoriesXML():
    categories = session.query(Category).all()
    return dicttoxml.dicttoxml({"categories" : [i.serialize for i in categories]})

# Get all the items for a specific category
@app.route('/category/<int:category_id>/XML/')
def categoryItemsXML(category_id):
    items = session.query(Item).filter(Item.category_id == category_id).all()
    return dicttoxml.dicttoxml({"items" : [i.serialize for i in items]})
    
    
    
"""
TEMPLATES/ WEB
"""

        
# Show catalog home
@app.route('/')
@app.route('/catalog/')
def catalog():
    categories = session.query(Category).order_by(asc(Category.name))
    counts = {}
    for category in categories:
        #category.item_count = 
        count = session.query(Item).filter(Item.category_id==category.id).count()
        counts[category.id] = count
    # Show the 5 most recent items
    items = session.query(Item).order_by(Item.created_date.desc()).limit(5)
    
    template = 'catalogPublic.html'
    if 'username' in login_session:
        template = 'catalog.html'
    return render_template(template, categories = categories, counts = counts, items = items)

    
# Show Category
@app.route('/category/<int:category_id>/')
def showCategory(category_id):
    categories = session.query(Category).order_by(asc(Category.name))
    counts = {}
    for category in categories:
        count = session.query(Item).filter(Item.category_id==category.id).count()
        counts[category.id] = count
        
    category = session.query(Category).filter_by(id = category_id).one()
    items = session.query(Item).filter_by(category_id = category.id).order_by(Item.name.asc())
    
    template = 'showCategoryPublic.html'
    if 'username' in login_session:
        template = 'showCategory.html'
        
    return render_template(template, categories = categories, category = category, counts = counts, items = items)


# New Category
@app.route('/category/new/',methods=['GET','POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
        
    if request.method == 'POST':
        errors = []
        # check blank
        if request.form['name'] == "":
            errors.append('Category Name is required.')
        # check duplicate
        if session.query(Category).filter(Category.name == request.form['name']).count()>0:
            errors.append('That category already exists.')
        # too long - not pretty
        if len(request.form['name'])>36:
            errors.append('Please limit category name to 32 characters or less.')
        if len(errors)>0:
            return render_template('newCategory.html', errors = errors, name = request.form['name'])
        else:
            newCategory = Category(name = request.form['name'], user_id=login_session['user_id'])
            session.add(newCategory)
            session.commit()
            flash('New Category added.')
            return redirect(url_for('catalog'))
    else:
        return render_template('newCategory.html')

# Edit Category
@app.route('/category/<int:category_id>/edit',methods=['GET','POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
        
    category = session.query(Category).filter_by(id = category_id).one()
    if category.user_id != login_session['user_id']:
        flash("This category was created by another user.")
        return redirect('/catalog/')
    
    if request.method == 'POST':
        errors = []
        # check blank
        if request.form['name'] == "":
            errors.append('Category Name is required.')
        # check duplicate
        if session.query(Category).filter(Category.name == request.form['name'], Category.id != category_id).count()>0:
            errors.append('That category already exists.')
        # too long - not pretty
        if len(request.form['name'])>36:
            errors.append('Please limit category name to 32 characters or less.')
        if len(errors)>0:
            return render_template('editCategory.html', category = category, errors = errors, name = request.form['name'])
        else:
            category.name = request.form['name']
            session.add(category)
            session.commit()
            flash('Category %s has been updated.' % category.name)
            return redirect(url_for('showCategory', category_id = category.id))
    else:
        return render_template('editCategory.html', category = category, name = category.name)    
  
# Delete Category
@app.route('/category/<int:category_id>/delete/', methods=['GET','POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
        
    category = session.query(Category).filter_by(id = category_id).one()
    if category.user_id != login_session['user_id']:
        flash("This category was created by another user.")
        return redirect(url_for('showCategory', category_id = category_id))
        
    if request.method == 'POST':
        if verifyNonce(login_session['state'],request.form['nonce']):
            session.delete(category)
            session.commit()
            flash('Category %s has been deleted.' % category.name)
            return redirect(url_for('catalog'))
        else:
            flash("Permission denied. Possible CSRF.");
            return redirect(url_for('showCategory', category_id = category_id))
    else:
        nonce = getNonce()
        return render_template('deleteCategory.html', category = category, nonce = nonce)  




# Show Item
@app.route('/item/<int:item_id>/')
def showItem(item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    
    template = 'showItemPublic.html'
    if 'username' in login_session and item.user_id == login_session['user_id']:
        template = 'showItem.html'
    return render_template(template, item = item)
    
# New Item
@app.route('/item/new/',methods=['GET','POST'])
@app.route('/item/<int:category_id>/new/',methods=['GET','POST'])
def newItem(category_id=''):
    if 'username' not in login_session:
        return redirect('/login')
    
    item = Item()
    item.category_id = category_id
    
    categories = session.query(Category).order_by(asc(Category.name))
   
    if request.method == 'POST':
        errors = []
        # check blank
        if request.form['name'] == "" or request.form['category_id'] == "" or request.form['description'] == "" or request.form['price'] == "":
            errors.append('Name, Category, Description, and Price are required.')
        # check duplicate
        if session.query(Item).filter(Item.name == request.form['name'], Item.category_id == request.form['category_id']).count()>0:
            errors.append('That item already exists in that category.')
        # too long - not pretty
        if len(request.form['name'])>36:
            errors.append('Please limit item name to 32 characters or less.')
 
        # set these values so we can show them what they tried to enter without passing as separate params
        item.name = request.form['name']
        item.category_id = request.form['category_id']
        item.description = request.form['description']
        item.price = request.form['price']
        item.picture = request.form['picture']
        item.user_id = login_session['user_id']
        
        if len(errors)>0:
            return render_template('newItem.html', category_id = category_id, categories = categories, item = item, errors = errors)
        else:
            session.add(item)
            session.commit()
            flash('Item %s has been added to the catalog.' % item.name)
            return redirect(url_for('showCategory', category_id = item.category.id))
    else:
        return render_template('newItem.html', category_id = category_id, categories = categories, item = item)
        
# Edit Item
@app.route('/item/<int:item_id>/edit/',methods=['GET','POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')
        
    item = session.query(Item).filter_by(id = item_id).one()
    if item.user_id != login_session['user_id']:
        flash("This item was created by another user.")
        return redirect(url_for('showItem', item_id = item.id))
    
    categories = session.query(Category).order_by(asc(Category.name))
    
    if request.method == 'POST':
        errors = []
        # check blank
        if request.form['name'] == "" or request.form['category_id'] == "" or request.form['description'] == "" or request.form['price'] == "":
            errors.append('Name, Category, Description, and Price are required.')
        # check duplicate
        if session.query(Item).filter(Item.name == request.form['name'], Item.category_id == request.form['category_id'], Item.id != item_id).count()>0:
            errors.append('That item already exists in that category.')
        # too long - not pretty
        if len(request.form['name'])>36:
            errors.append('Please limit item name to 32 characters or less.')
 
        # set these values so we can show them what they tried to enter without passing as separate params
        item.name = request.form['name']
        item.category_id = request.form['category_id']
        item.description = request.form['description']
        item.price = request.form['price']
        item.picture = request.form['picture']
        item.user_id = login_session['user_id']
            
        if len(errors)>0:
            return render_template('editItem.html', item = item, categories = categories, errors = errors)
        else:
            session.add(item)
            session.commit()
            flash('Item %s has been updated.' % item.name)
            return redirect(url_for('showCategory', category_id = item.category.id))
    else:
        return render_template('editItem.html', item = item, categories = categories)  
    
    
# Delete Item
@app.route('/item/<int:item_id>/delete/',methods=['GET','POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')
        
    item = session.query(Item).filter_by(id = item_id).one()
    if item.user_id != login_session['user_id']:
        flash("This item was created by another user.")
        return redirect(url_for('showItem', item_id = item.id))
        
    if request.method == 'POST':
        if verifyNonce(login_session['state'],request.form['nonce']):
            session.delete(item)
            session.commit()
            flash('Item %s has been deleted.' % item.name)
            return redirect(url_for('catalog'))
        else:
            flash("Permission denied. Possible CSRF.");
            return redirect(url_for('showItem', item_id = item.id))
    else:
        nonce = getNonce()
        return render_template('deleteItem.html', item = item, nonce = nonce)  
    
""" 
            BEGIN USER METHODS
"""
            
# Get User id (by email) or return null (None in python)
def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

        
        
# Get User Information
def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user
        
        
# Create a NEW USER
def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

"""
            END USER METHODS
""" 
  
  
if __name__ == '__main__':
  app.secret_key = 'C9D7886A56D4F1367B5F97FDA39C8'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
  #app.run(host = '0.0.0.0', port=80)
  
  
  