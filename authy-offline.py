#!/usr/bin/env python3

import frida, json
import xml.etree.ElementTree as ET
import pyotp, qrcode, io

jsCode = """
    Java.perform(function() {
        function readFile(fileName){
            // Load required classes
            var String = Java.use("java.lang.String");
            var Files = Java.use("java.nio.file.Files");
            var Paths = Java.use("java.nio.file.Paths");
            var URI = Java.use("java.net.URI");

            var pathName = "file://" + fileName;
            var path = Paths.get(URI.create(pathName));
            // read file contents
            var fileBytes = Files.readAllBytes(path);
            // Convert to string from bytes
            var ret = String.$new(fileBytes);

            return ret
        } 

        try {
            // XML contains &quot; HTML double quotes which should be replaced
            var contents = readFile("/data/user/0/com.authy.authy/shared_prefs/com.authy.storage.tokens.authenticator.xml");
            //console.log("File:\\n\\n" + contents)
            send(contents.toString());
            //send({ level: "info", message: "Found method: " + contents.toString() })
        } catch (error) {
            console.log("[!] " + error);
        }
    });
"""

# Support Aegis plain JSON feature
# e.g. https://github.com/beemdevelopment/Aegis/blob/master/app/src/test/resources/com/beemdevelopment/aegis/importers/aegis_plain.json
aegis_plain = {
    "version": 1,
    "header": {
        "slots": None,
        "params": None
    },
    "db": {
        "version": 1,
        "entries": []   
    }
}

def onMessage(message, data):
    if message["type"] == 'send':
        # print(u"[*] {0}".format(message['payload']))
        print("[+] Extracting Authy TOTP Tokens... ")
        # Do some magic
        dataFile = message['payload'].replace('&quot;','"')
        parseXML(dataFile)
        print("-----------------------------------------------------")
        print(u"{0}".format(dataFile))
    else:
        print(message)

def exportJSON(data):
    # Create a aegis_plain export file
    with open('exported.json', 'w') as f:
        json.dump(data, f)

def parseXML(dataFile):
    root = ET.fromstring(dataFile) 
    data = json.loads(root[1].text)
    # Count number of TOTPs
    numTokens = len(data)
    if numTokens > 0:
        print(f"[+] Found ({numTokens}) TOTP tokens\n")
    else:
        print(f"[!] No TOTP tokens found\n")
        exit(1)
    
    # QR configuration
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=5,
        border=2,
    )

    for i in range(len(data)):
        # TODO handle different accountTypes better
        if data[i]["accountType"] != "authenticator":
            print(f"[!] Attempting to dump unsupported account type '{data[i]["accountType"]}'\n")
        
        # Assign values and default empty ones
        name = data[i].get('originalName', None)
        issuer = data[i].get('originalIssuer', None)
        secret = data[i].get('decryptedSecret', None)
        timestamp = data[i].get('timestamp', None)
        digits = data[i].get('digits', None)

        # Create a Aegis_plain entry template
        entry = {
            "type": "totp",
            "uuid": "",
            "name": name,
            "issuer": issuer,
            "icon": None,
            "info": {
                "secret": secret,
                "algo": "SHA256",
                "digits": digits,
                "period": 30 # default 30 seconds
            }
        }
        aegis_plain["db"]["entries"].append(entry)
        # Display info about each result
        print(f"Name:    {name}")
        print(f"Issuer:  {issuer}")
        print(f"Secret:  {secret}")
        print(f"Timestamp:  {timestamp}")

        if secret and digits == None:
            # No point of generating anything
            pass

        # Quickly generate a TOTP to compare with the app
        totp = pyotp.TOTP(secret, digits=digits, interval=30).now()
        print(f"TOTP: {totp} (compare with app!)")

        # Generate a QR code with TOTP secret
        otpauth = f"otpauth://totp/{name}?secret={secret}&digits={digits}&issuer={issuer}&period=30"
        qr.add_data(otpauth)
        f = io.StringIO()
        # Print to console
        qr.print_ascii(out=f)
        f.seek(0)
        print(f.read())
        # Must be cleared 
        qr.clear()
    
    # write JSON to file
    exportJSON(aegis_plain)
    
# Show what Frida script we are running
#print(jsCode)

device = frida.get_usb_device()
try:
    pid = device.spawn(["com.authy.authy"])
except frida.NotSupportedError:
    print("[!] Frida server might not be running.")
    exit(1)

process = device.attach(pid)
script = process.create_script(jsCode)
script.on('message', onMessage)
script.load()
device.resume(pid)
# Prevent script from ending
input()
