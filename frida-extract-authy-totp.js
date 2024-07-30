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
            console.log("File:\\n\\n" + contents)
        } catch (error) {
            console.log("[!] " + error);
        }
    });
