import http.server
import socketserver
import json
import time
import jwt
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
from collections import OrderedDict
keys = {}
def RSAkeypairgeneration(kid, expiry):
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size= 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    
    #Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Store key pair with kty: "RSA"
    keys[kid] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "kid": kid,
        "expiry": expiry,
    }
    
def generate_key(expiry):
    kid = str(len(keys) + 1)
    RSAkeypairgeneration(kid,expiry)
    return kid

class JWKSHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            #Generate JWKS response with non-expired keys  
            current_time = int(time.time())
            jwks = {"keys": []}
            for kid, key_data in keys.items():
                if key_data["expiry"] > current_time:
                    public_key = serialization.load_pem_public_key(key_data["public_key"],backend = default_backend())
                    #public key numbers
                    numbers = public_key.public_numbers()
                    mod = numbers.n
                    mod_bytes = mod.to_bytes((mod.bit_length() + 7) // 8, byteorder = "big")
                    #mod_base64url = base64.urlsafe_b64encode(mod_bytes).decode("utf-8").rstrip("=")
                    exp = numbers.e
                    exp_bytes = exp.to_bytes((exp.bit_length() + 7) // 8, byteorder = "big")
                    #exp_base64url = base64.urlsafe_b64encode(exp_bytes).decode("utf-8").rstrip("=")
                    mod_base64url = base64.urlsafe_b64encode(mod.to_bytes((mod.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip("=")
                    exp_base64url = base64.urlsafe_b64encode(exp.to_bytes((exp.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip("=")
                    #add key to JWKS dict
                    jwks["keys"].append({
                        "kty": "RSA",
                        "use": "sig",
                        "n": mod_base64url,
                        "e": exp_base64url,
                        "alg":"RS256",
                        "kid": kid
                    })
            self.wfile.write(json.dumps(jwks).encode())
        else:
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
            self.wfile.write(json.dumps(response_data).encode())
    def do_POST(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            current_time = int(time.time())
            if "expired" in query_params and query_params["expired"][0].lower() == "true":
                print("FEIAFEEEEEEEEEEEEEEEEE")
                kid_expired = generate_key(current_time - 5000)
                kid_expired_headers = OrderedDict([
                    ("typ", "JWT"),
                    ("alg", "RS256"),
                    ("kid", kid_expired)
                ])
                print(kid_expired)
                private_key_expired = serialization.load_pem_private_key(keys[kid_expired]["private_key"], password=None,backend=default_backend())
                expired_token = jwt.encode({"sub": "user","exp": current_time - 5000}, private_key_expired, algorithm="RS256", headers=kid_expired_headers)
                response_data = {"exp" : current_time - 5000,"jwt": expired_token}
                self.wfile.write(json.dumps(response_data).encode())
                print(current_time)
            else:
                kid = generate_key(current_time + 3600)
                print(kid)
                kid_headers = OrderedDict([
                    ("typ", "JWT"),
                    ("alg", "RS256"),
                    ("kid", kid)
                ])
                private_key = serialization.load_pem_private_key(keys[kid]["private_key"], password = None, backend=default_backend())
                valid_token = jwt.encode({"sub":"user", "exp": current_time + 3600}, private_key, algorithm="RS256", headers=kid_headers)
                response_data = {"exp" : current_time + 3600,"jwt": valid_token}
                self.wfile.write(json.dumps(response_data).encode())
                #Generate expired JWT
                print(query_params)
            
        else:
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
            self.wfile.write(json.dumps(response_data).encode())
    def do_PUT(self):
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
        self.wfile.write(json.dumps(response_data).encode())
    def do_PATCH(self):
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
        self.wfile.write(json.dumps(response_data).encode())
    def do_DELETE(self):
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
        self.wfile.write(json.dumps(response_data).encode())        
    def do_HEAD(self):
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"error": "Method Not Allowed", "message": "The HTTP method is not allowed for this resource."}
if __name__ == "__main__":
    PORT = 8080
    with socketserver.TCPServer(("", PORT), JWKSHandler) as httpd:
        print(f"Serving on port {PORT}...")
        httpd.serve_forever()