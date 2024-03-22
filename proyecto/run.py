from app.seguridad import app as seguridad_app
from app.fiabilidad import *

if __name__ == "__main__":
  if seguridad_app.debug:
      seguridad_app.run(debug=True)
  else:
      seguridad_app.run(debug=False, ssl_context='adhoc')