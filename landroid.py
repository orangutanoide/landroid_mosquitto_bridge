import paho.mqtt.client as paho
from getpass import getpass
from OpenSSL import crypto
import requests
import logging
import base64
import time
import uuid
import json
import ssl
import sys

logger = logging.getLogger(__name__)

API_TOKEN = "qiJNz3waS4I99FPvTaPt2C2R46WXYdhw"
KEY_FILE = 'aws_key.pem'
CRT_FILE = 'aws_crt.pem'

class LandroidCloud:

    def __init__(self, username, password):
        self.apiUrl = "api.worxlandroid.com"
        self.apiVersion = "/api/v2"
        self.type = " "

        self.uuid = str(uuid.uuid1())

        self.token = API_TOKEN

        # get user token, and type token
        self.retrieveUserToken(username, password)

        # get mqtt end point from user profile
        self.retrieveUserProfile()

        # get aws crt and key
        self.retrieveAwsCertificate()

        # get the board model
        self.getProductItems()

        self.topic = self.mqtt_topic_prefix + '/' + self.macAddress
        logging.info("Final topic: '%s'" % self.topic)

    def get_params(self):
        return self.uuid, self.topic, self.mqtt_endpoint

    def retrieveUserToken(self, username, password):
        path = "/oauth/token"
        data = {"username": username,
                "password": password,
                "grant_type": "password",
                "uuid": self.uuid,
                "client_id": "1",
                "type": "app",
                "client_secret":"nCH3A0WvMYn66vGorjSrnGZ2YtjQWDiCvjg7jNxK",
                "scope":"*"}

        logging.info("Retrieving user token...")
        response = self.api('post', '/oauth/token', data)
        self.token = response["access_token"];
        self.type = response["token_type"];


    def retrieveUserProfile(self):
        logging.info("Retrieving user profile")
        response = self.api('get', '/users/me')
        self.mqtt_endpoint = response["mqtt_endpoint"]
        logging.info("mqtt endpoint: %s" % self.mqtt_endpoint)


    def getProductItems(self):
        response = self.api('get', '/product-items')
        logging.info("Searching board...")
        if "mower_sel" in response:
            self.macAddress = response["mower_sel"]["mac_address"]
            self.product_id = response["mower_sel"]["product_id"]
        else:
            self.macAddress = response[0]["mac_address"]
            self.product_id = response[0]["product_id"]

        self.boards = self.api('get', '/boards')

        self.products = self.api('get', '/products')

        for product in self.products:
            if product["id"] == self.product_id:
                for board in self.boards:
                    if product["board_id"] == board["id"]:
                        self.mqtt_topic_prefix = board["mqtt_topic_prefix"]
                        logging.info("Board %s selected" % self.mqtt_topic_prefix)
                        return

        logging.error("Coluld not find Board in List")
        sys.exit(1)


    def retrieveAwsCertificate(self):
        logging.info("Retrieving aws certificate...")
        response = self.api('get', '/users/certificate')
        p12response = response["pkcs12"]

        p12 = crypto.load_pkcs12(base64.b64decode(p12response))

        key_file = open(KEY_FILE, 'wb')
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey()))
        key_file.close()

        crt_file = open(CRT_FILE, 'wb')
        crt_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate()))
        crt_file.close()

        logging.info("key and certificate saved")

    def api(self, method, path, data = None):

        auth_header = (self.type + " " + self.token).strip()
        # print("headr:",auth_header)
        headers = {
        "Content-Type": "application/json",
        "Authorization": (self.type + " " + self.token).strip()
        }
        if (data):
            data = json.dumps(data).encode('UTF-8')
            headers["Content-Length"] = str(len(data)).encode('UTF-8')

        url = 'https://' + self.apiUrl + "/api/v2" + path

        if method == "post":
            r = requests.post(url = url, headers = headers, data = data)
        else:
            r = requests.get(url = url, headers = headers, data = data)

        if r.status_code == 200:
            response = json.loads(r.text)
            return response
        else:
            logging.error("Something wrong with api %s, %s, %s" % (method, path, data))
            logging.error(r.text)
            logging.error(r.headers)
            sys.exit(1)

def write2file(f, line):
    f.write(line.encode('utf-8'))

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    print("\nHello. I will try to help you to configure mosquitto as bridge to aws server.\n")
    print("Please introduce your credentials for worxlandroid.com:")

    username = input("Username (email): ")
    password = getpass()

    uuid, topic, end_point = LandroidCloud(username, password).get_params()

    cp = '/etc/mosquitto/certs/'
    print("Process finished!\n")

    print("Certificate and private key files are saved as %s and %s\n" % (CRT_FILE, KEY_FILE))
    print("You need to:")
    print("")
    print("1. Move this files to mosquito certs folder (usually %s)" % cp)
    print("sudo mv %s %s" % (CRT_FILE, cp))
    print("sudo mv %s %s" % (KEY_FILE, cp))
    print("")
    print("2. Set the proper permissions to those files (usually only user mosquitto can read them)")
    print("sudo chown mosquitto:mosquitto %s%s %s%s" % (cp, CRT_FILE, cp, KEY_FILE))
    print("sudo chmod 400 %s%s %s%s" % (cp, CRT_FILE, cp, KEY_FILE))
    print("")
    print("3. You need AT LEAST one CA file for mosquitto TLS communications. If you have one already, skip this. If not, move the ca_example.pem to the certs folder, and set permissions")
    print("sudo mv ca_example.pem %s" % (cp))
    print("sudo chown mosquitto:mosquitto %sca_example.pem" % (cp))
    print("sudo chmod 400 %sca_example.pem" % (cp))
    print("")

    mf = open('landroid-aws-bridge.conf', 'wb')
    write2file(mf, '# landroid aws bridge configuration\n')
    write2file(mf, '\n')
    write2file(mf, "connection landroid-aws-bridge\n")
    write2file(mf, "address %s:8883\n" % end_point)
    write2file(mf, "\n")
    write2file(mf, "# avoid send unsubscribe commands to remote server\n")
    write2file(mf, "bridge_attempt_unsubscribe false\n")
    write2file(mf, "\n")
    write2file(mf, "# tls files and settings\n")
    write2file(mf, "bridge_protocol_version mqttv311\n")
    write2file(mf, "bridge_insecure false\n")
    write2file(mf, "tls_version tlsv1.2\n")
    write2file(mf, "\n")
    write2file(mf, "bridge_cafile /etc/mosquitto/certs/ca.pem\n")
    write2file(mf, "bridge_certfile /etc/mosquitto/certs/%s\n" % CRT_FILE)
    write2file(mf, "bridge_keyfile /etc/mosquitto/certs/%s\n" % KEY_FILE)
    write2file(mf, "\n")
    write2file(mf, "# topic to subscribe in remote (aws) server\n")
    write2file(mf, "topic %s/commandOut in" % topic)
    write2file(mf, "\n")
    write2file(mf, "cleansession true\n")
    write2file(mf, "clientid android-%s\n" % uuid)
    write2file(mf, "start_type automatic\n")
    write2file(mf, "notifications false\n")
    write2file(mf, "\n")
    mf.close()
    print("4. The file 'landroid-aws-bridge.conf' was created. You need to add it to mosquitto configuration (usually putting in /etc/mosquitto/conf.d/ folder)")
    print("sudo mv landroid-aws-bridge.conf /etc/mosquitto/conf.d/");
    print("sudo chown mosquitto:mosquitto /etc/mosquitto/conf.d/");
    print("sudo chmod 400 /etc/mosquitto/conf.d/landroid-aws-bridge.conf");
    print("")
    print("5. Restart mosquito\n")


