## Description

The purpose of this project is to emulate a website that hosts a catalog of
items within various categories (i.e. a sport such as soccer under a sports
category)

## How to run this project

1) Open the terminal and navigate to the project directory
2) Run the command `vagrant up` in the terminal to configure the virtual machine
3) Run the command `vagrant ssh` to boot the virtual machine
4) Use the command `cd /vagrant` to enter the shared folder
5) Navigate to the directory with the file `views.py`
6) Run `views.py` with the command `python views.py` to start the server
7) Type `localhost:8000` into your browser to go to the site

***NOTICE*** BEFORE RUNNING `views.py`, YOU MUST INSTALL THESE MODULES:
* flask_login
* requests

To install these modules, run the commands `sudo pip install flask_login` and
`sudo pip install requests` in your virtual machine inside the shared `/vagrant`
folder.

## Accessing the JSON format files

To access the json formatted links, follow these URIs:
* `/catalog/json`
* `/catalog/<string:cat_name>/json` -OR- `/catalog/<string:cat_name>/items/json`
* `/catalog/<string:cat_name>/<string:item_name>/json`
