from flask import Flask
from config import Config
from models import db, init_db
from flask_login import LoginManager
from views.auth import auth_bp
from views.user import user_bp
from views.admin import adm_bp
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config.from_object(Config)

login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

init_db(app)
login_manager.init_app(app)
migrate = Migrate(app, db)
    

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(adm_bp, url_prefix='/admin')


@login_manager.user_loader
def load_user(user_id):
    from models import User, db
    return db.session.get(User, int(user_id))

if __name__ == '__main__':
 
    app.run(host='0.0.0.0', port=5000, debug=True)