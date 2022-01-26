from flask import Blueprint
from flask import Flask, render_template, request, make_response, send_from_directory
from flask_login import login_required, current_user
from functools import wraps
from . import admin_login_required, db, get_user_role
from .models import User



def populate_db():

    # https://www.trash-mail.com/inbox/
    user = User.query.filter_by(email='adam.smith@trash-mail.com').first()

    if not user:
        new_user = User(email='adam.smith@trash-mail.com',
                        password='$argon2id$v=19$m=65536,t=3,p=4$NJf1sG5DqAE0HP2tMkw/ng$zvtwEUmm6hpazvLJCT+ZQa9o3jxroeqW/jWHqwGY8j0',
                        cardinfo='EMrMX3FA2PyFFb+njz1AGKP1CyVHoc9OHgYKuGUpm4OR6e0IDs2E5vCRhO6TXHn9QlcqlDwwxqP3sgneAOIX2G2+hA==',
                        infosalt='|Ry19+gjk/L,@sytB{I8fe&U7#jVuy8`7gH2py%Y:b\7x1!]|.',
                        role="admin")

        db.session.add(new_user)
        db.session.commit()

