# Sef
Secure and encrypt your .env file using new .sef file stands for "Secure Encrypted File"

# Usage
# ENSURE TO USE SLASH AFTER PROVIDING PATH TO A FILE!

```go
//Generate security 
var GSErr = Sef.GenerateSecurity("security/");

if (len(GSErr) != 0 ){
  log.Fatal("Could not generate security!");
}
```

var values, CSErr = Sef.CreateSef("./", "security/");
if (len(CSErr) != 0 ){
  log.Fatal("Could not create .sef file!");
}

var keys, GKErr = Sef.GetKeys("security/");
if (len(GKErr) != 0) {
  log.Fatal("Could not read security keys!");
}

var ECErr = keys.EncryptENV(values);
if (len(ECErr) != 0 ){
  log.Fatal("Could not encrypt .env file!")
}

var sef *Sef.SefGetters = Sef.DefineSefGetters(keys, "security/");
var data, GErr = sef.Get(1);
if (len(GErr) != 0){
  log.Fatal("Could not get value");
}

fmt.Println(string(data));
