from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret" # Cambiar por el que se conveniente
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401


# Funcion que se ejecutará siempre de primero antes de que la consulta llegue a la ruta solicitada
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        almacenista = get_jwt_identity()
        if almacenista["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method,almacenista["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied1"}), 401
        else:
            return jsonify({"message": "Permission denied2"}), 401


def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso


############################almacenista########################################
@app.route("/almacenista", methods=['GET'])
def getAlmacenistas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenista'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/almacenista", methods=['POST'])
def crearAlmacenista():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenista'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/almacenista/<string:id>", methods=['GET'])
def getAlmacenista(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenista/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/almacenista/<string:id>", methods=['PUT'])
def modificarAlmacenista(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenista/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/almacenista/<string:id>", methods=['DELETE'])
def eliminarAlmacenista(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenista/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################Producto########################################
@app.route("/producto", methods=['GET'])
def getProductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/producto'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/producto", methods=['POST'])
def crearProducto():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/producto'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/producto/<string:id>", methods=['GET'])
def getProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/producto/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/producto/<string:id>", methods=['PUT'])
def modificarProducto(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/producto/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/producto/<string:id>", methods=['DELETE'])
def eliminarProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/producto/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################Proveedor########################################
@app.route("/proveedor", methods=['GET'])
def getProveedores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedor'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/proveedor", methods=['POST'])
def crearProveedor():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedor'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedor/<string:id>", methods=['GET'])
def getProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedor/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/proveedor/<string:id>", methods=['PUT'])
def modificarProveedor(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedor/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedor/<string:id>", methods=['DELETE'])
def eliminarProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedor/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################################Inventario###############################################################
@app.route("/inventario", methods=['GET'])
def getInventarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventario'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventario", methods=['POST'])
def crearInventario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventario'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventario/<string:id>", methods=['GET'])
def getInventario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventario/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventario/<string:id_inventario>", methods=['PUT'])
def modificarInventario(id_inventario):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventario/' + id_inventario
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventario/<string:id_inventario>", methods=['DELETE'])
def eliminarInventario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventario/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################Inventario-Producto########################################
@app.route("/inventarioproducto", methods=['GET'])
def getInventarioProductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproducto'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproducto", methods=['POST'])
def crearInventarioProducto():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproducto'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproducto/<string:id>", methods=['GET'])
def getInventarioProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproducto/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproducto/<string:id_inventarioproducto>", methods=['PUT'])
def modificarInventarioProducto(id_inventarioproducto):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproducto/' + id_inventarioproducto
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproducto/<string:id_inventarioproducto>", methods=['DELETE'])
def eliminarInventarioProducto(id_inventarioproducto):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproducto/' + id_inventarioproducto
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################Usuario-Almacenista########################################
@app.route("/usuarioalmacenista", methods=['GET'])
def getUsuarioAlmacenistas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/usuarioalmacenista'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/usuarioalmacenista", methods=['POST'])
def crearUsuarioAlmacenista():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/usuarioalmacenista'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/usuarioalmacenista/<string:id>", methods=['GET'])
def getUsuarioAlmacenista(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/usuarioalmacenista/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/usuarioalmacenista/<string:id_usuarioalmacenista>", methods=['PUT'])
def modificarUsuarioAlmacenista(id_usuarioalmacenista):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/usuarioalmacenista/' + id_usuarioalmacenista
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/usuarioalmacenista/<string:id_usuarioalmacenista>", methods=['DELETE'])
def eliminarUsuarioAlmacenista(id_usuarioalmacenista):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/usuarioalmacenista/' + id_usuarioalmacenista
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
