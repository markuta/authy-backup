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

    known_keys = {
        # fields we use:
        "accountType", "decryptedSecret", "digits", "name", "originalIssuer", "originalName", "timestamp",
        # fields we know we don't need:
        "encryptedSecret", "salt", "key_derivation_iterations", "upload_state", "hidden", "id", "isNew", "logo",
    }
    for i in range(len(data)):
        # TODO handle different accountTypes better
        account_type = data[i].get('accountType', None)
        if account_type != "authenticator":
            print(f"[+] Attempting to dump unsupported account type '{data[i]["accountType"]}'\n")

        if set(data[i].keys()) - known_keys:
            print(f"[!] Warning: unexpected keys in item, may impact generation: {set(data[i].keys()) - known_keys}")

        # Assign values and default empty ones
        original_name = data[i].get('originalName', None)
        name = data[i].get('name', original_name)
        issuer = data[i].get('originalIssuer', None)
        secret = data[i].get('decryptedSecret', None)
        timestamp = data[i].get('timestamp', None)
        digits = data[i].get('digits', None)

        if original_name is not None and original_name.replace(" ", "") != name.replace(" ", ""):
            # generally whichever name contains ":" is more reliable (contains issuer)
            print(f"[!] Warning: originalName ({original_name}) and name ({name}) differ, using heuristic (if it contains :) to guess best name for export")
            if ":" in original_name and ":" not in name:
                name = original_name

        if issuer is None and ":" not in (name or "") and account_type != "authenticator":
            # account_type often indicates the issuer (e.g. microsoft) when issuer is missing
            # if name doesn't contain issuer (i.e. doesn't contain :), set this fallback issuer
            issuer = account_type

        # Create a Aegis_plain entry template
        # TODO check value before assignment
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
        print(f"Digits:  {secret}")
        print(f"Timestamp:  {timestamp}")

        # TODO check all of them...
        if secret is None:
            print(f"[!] Warning: secret field empty or not found")
            continue
        elif digits is None:
            print(f"[!] Warning: digits field empty or not found")
            continue
        else:
            # Quickly generate a TOTP to compare with the app
            try:
                # TODO check secret is valid base32
                totp = pyotp.TOTP(secret, digits=6, interval=30).now()
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
            except:
                print(f"[!] Warning: issue with generating OTP code")
    
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
