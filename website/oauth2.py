import sys
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer, ResourceProtector)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core import UserInfo
from authlib.jose import jwk
from werkzeug.security import gen_salt
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

def read_file(filename):
    try:
        with open(filename, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"required file {filename} not found, exiting")
        sys.exit(1)

JWT_CONFIG = { }

def exists_nonce(nonce, req):
    exists = OAuth2AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)


def generate_user_info(user, scope):
    return UserInfo(sub=str(user.id), name=user.username)


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        return gen_salt(48)

    def save_authorization_code(self, code, request):
        client = request.client
        nonce = request.data.get('nonce')
        item = OAuth2AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(item)
        db.session.commit()

    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


authorization = AuthorizationServer()
require_oauth = ResourceProtector()

PUBKEY = {}

def pubkey():
    return { "keys": [PUBKEY] }

def get_metadata():
    base_url = JWT_CONFIG["iss"]
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "jwks_uri": f"{base_url}/static/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email"],
        "response_types_supported": ["code"],
        "userinfo_signing_alg_values_supported": ["RS256"]
    }

def config_oauth(app):
    global PUBKEY
    global JWT_CONFIG

    JWT_CONFIG['iss'] = app.config["OAUTH2_JWT_ISS"]
    JWT_CONFIG['key'] = jwk.dumps(read_file(app.config["OAUTH2_JWT_RSA_KEY"]), "RSA")
    JWT_CONFIG['key']['kid'] = app.config["OAUTH2_JWK_KEY_NAME"]
    JWT_CONFIG['alg'] = app.config["OAUTH2_JWT_ALG"]
    JWT_CONFIG['exp'] = app.config["OAUTH2_JWT_EXP"]

    PUBKEY = jwk.dumps(read_file(app.config["OAUTH2_JWT_PUBLIC_KEY"]), "RSA")
    PUBKEY["kid"] = app.config["OAUTH2_JWK_KEY_NAME"]

    query_client = create_query_client_func(db.session, OAuth2Client)
    save_token = create_save_token_func(db.session, OAuth2Token)
    authorization.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # support all openid grants
    authorization.register_grant(AuthorizationCodeGrant, [
        OpenIDCode(require_nonce=app.config['REQUIRE_NONCE']),
    ])

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
