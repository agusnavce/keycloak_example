import os
import json
import logging
from flask import Flask, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)


@app.route('/token_login/', methods=['POST'])
def get_token():
    body = request.get_json()
    for field in ['username', 'password']:
        if field not in body:
            return error(f"Field {field} is missing!"), 400
    data = {
        'grant_type': 'password',
        'client_id': os.getenv('CLIENT_ID'),
        'client_secret': os.getenv('CLIENT_SECRET'),
        'username': body['username'],
        'password': body['password']
    }
    url = ''.join([
        os.getenv('KEYCLOAK_URI'),
        'realms/',
        os.getenv('REALM'),
        '/protocol/openid-connect/token'
    ])
    response = requests.post(url, data=data)
    if response.status_code > 200:
        message = "Error en username/password"
        return error(message), 400
    tokens_data = response.json()
    ret = {
        'tokens': {"access_token": tokens_data['access_token'],
                   "refresh_token": tokens_data['refresh_token'], }
    }
    return jsonify(ret), 200


@app.route('/token_refresh/', methods=['POST'])
def refresh_token():
    body = request.get_json()
    for field in ['refresh_token']:
        if field not in body:
            return error(f"Field {field} is missing!"), 400
    data = {
        'grant_type': 'refresh_token',
        'client_id': os.getenv('CLIENT_ID'),
        'client_secret': os.getenv('CLIENT_SECRET'),
        'refresh_token': body['refresh_token'],
    }
    url = os.getenv('KEYCLOAK_URI') + 'realms/' + \
        os.getenv('REALM') + '/protocol/openid-connect/token'
    response = requests.post(url, data=data)
    if response.status_code != requests.codes.ok:
        return error("Error en refresh token"), 400
    data = response.json()
    ret = {
        "access_token": data['access_token'],
        "refresh_token": data['refresh_token']
    }
    return jsonify(ret), 200


@auth.route('/users/', methods=['POST'])
def create_user():
    try:
        body = request.get_json()
        endpoint = '/users'
        data = {
            "email": body.get('email'),
            "username": body.get('email'),
            "firstName": body.get('name'),
            "lastName": body.get('sirname'),
            "credentials": [{"value": body.get('password'), "type": 'password', 'temporary': False}],
            "enabled": True,
            "emailVerified": False
        }
        response = keycloak_post(endpoint, data)
    except KeycloakAdminError as e:
        try:
            message = e.response.json().get('errorMessage')
        except Exception as err:
            message = e.message
        app.logger.error(e.traceback())
        return error(message), 400
    except Exception as e:
        print(e)
        return error('Error with keycloak'), 400
    return "", 204


@app.errorhandler(404)
def not_found(e):
    return error("No exite la ruta para la url deseada en esta api"), 404


@app.errorhandler(405)
def doesnt_exist(e):
    return error("No exite la ruta para la url deseada en esta api"), 405


def error(message):
    return jsonify({
        'success': False,
        'message': message
    })


def keycloak_post(endpoint, data):
    """
    Realiza un POST request a Keycloak
    :param {string} endpoint Keycloak endpoint
    :data {object} data Keycloak data object
    :return {Response} request response object
    """
    url = os.getenv('KEYCLOAK_URI') + 'admin/realms/' + \
        os.getenv('REALM') + endpoint
    headers = get_keycloak_headers()
    response = requests.post(url, headers=headers, json=data)
    if response.status_code >= 300:
        app.logger.error(response.text)
        raise KeycloakAdminError(response)
    return response


def get_keycloak_headers():
    """
    Devuelve los headers necesarios para comunicarlos con la API de Keycloak
    utilizando el usuario de administración del Realm.
    :return {object} Objeto con headers para API de Keycloak
    """
    return {
        'Authorization': 'Bearer ' + get_keycloak_access_token(),
        'Content-Type': 'application/json'
    }


def get_keycloak_access_token():
    """
    Devuelve los tokens del usuario `admin` de Keycloak
    :returns {string} Keycloak admin user access_token
    """
    data = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': os.getenv('ADMIN_USER'),
        'password': os.getenv('ADMIN_PASS')
    }
    response = requests.post(os.getenv('KEYCLOAK_URI') + 'realms/' +
                             os.getenv('REALM') + '/protocol/openid-connect/token', data=data)
    if response.status_code != requests.codes.ok:
        raise KeycloakAdminTokenError(response)
    data = response.json()
    return data.get('access_token')


class KeycloakAdminError(Exception):
    message = 'Keycloak error'

    def __init__(self, response, message=None):
        if message is not None:
            self.message = message
        # Call the base class constructor with the parameters it needs
        super().__init__(self.message)
        # Now for your custom code...
        self.response = response

    def traceback(self):
        return traceback.format_exc()

    def __str__(self):
        return json.dumps({
            'message': self.message,
            'status_code': self.response.status_code,
            'text': self.response.text
        })
