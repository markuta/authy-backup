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

def onMessage(message, data):
    # print(message)
    # {'type': 'send', 'payload':'some strings'}
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


def parseXML(dataFile):
    root = ET.fromstring(dataFile) 
    #print(root[1].text)
    data = json.loads(root[1].text)
    # Count number of TOTPs
    numTokens = len(data)
    print(f"[+] Found ({numTokens}) TOTP tokens\n")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=5,
        border=2,
    )

    for i in range(len(data)):
        # verbose option to display the following
        #print(data[i]["accountType"])
        #print(data[i]["decryptedSecret"])
        #print(data[i]["digits"])
        #print(data[i]["originalName"])
        #print(data[i]["timestamp"])
        #print("\n")

        # Check the type
        if data[i]["accountType"] == "authenticator":

            # Quickly generate a TOTP to compare with the app
            totp = pyotp.TOTP(data[i]["decryptedSecret"], digits=data[i]["digits"], interval=30).now()
            
            # Display some info about the record
            print(f"Name: {data[i]["originalName"]}")
            print(f"Issuer: {data[i]["originalIssuer"]}")
            print(f"Secret: {data[i]["decryptedSecret"]}")
            print(f"Timestamp: {data[i]["timestamp"]}")
            print(f"TOTP: {totp} (compare with app)")

            # Generate a QR code with TOTP secret
            otpauth = f"otpauth://totp/{data[i]["originalName"]}?secret={data[i]["decryptedSecret"]}&digits={data[i]["digits"]}&issuer={data[i]["originalIssuer"]}&period=30"
            
            qr.add_data(otpauth)
            f = io.StringIO()
            qr.print_ascii(out=f)
            f.seek(0)
            print(f.read())
            # Must be cleared 
            qr.clear()
        else:
            print("[!] Skipping unsupported type...\n")
            pass

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
