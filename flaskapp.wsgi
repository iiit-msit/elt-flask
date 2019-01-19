import sys

#activate_this = '/devserver/www/eltflask/venv1/bin/activate_this.py'
#execfile(activate_this, dict(__file__=activate_this))

activate_this = '/devserver/www/flaskapp/venv/bin/activate_this.py'
with open(activate_this) as file_:
	exec(file_.read(), dict(__file__=activate_this))

sys.path.append('/devserver/www/flaskapp')
     
from gct import app as application
