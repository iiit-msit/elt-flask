#activate_this = '/var/www/eltflask/venv1/bin/activate_this.py'
#execfile(activate_this, dict(__file__=activate_this))

activate_this = '/var/www/eltflask/venv1/bin/activate_this.py'
with open(activate_this) as file_:
	exec(file_.read(), dict(__file__=activate_this))

import sys
     
sys.stdout = sys.stderr

sys.path.append('/var/www/eltflask')
     
from gct import app as application
