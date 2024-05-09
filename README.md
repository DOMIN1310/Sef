# Sef
Secure and encrypt your .env file using new .sef file stands for "Secure Encrypted File"

**REMEMBER TO ADD SLASH AFTER PATH AND TO CREATE THE DIRECTORY BEFORE EXECUTING!**

# Usage!

You also need to know that errors in this package are stored in slices so you have to handle then by checking its length and if its equal to 0 execute piece of code!

Generating security (.pem file which is the 32 bytes aes key and .key file the 12 bytes nonce) as the arguments you have to pass:
destiny path where the files will be stored.
```go
var GSErr = Sef.GenerateSecurity("security/"); // []error

//this is how to handle slice of errors
if (len(GSErr) != 0 ){
  log.Fatal("Could not generate security!");
}
```

To create .sef file you need to provide as arguments .env path and the destiny path.
```go
var values, CSErr = Sef.CreateSef("./", "security/"); //[]string with .env file values and []error

if (len(CSErr) != 0 ){
  log.Fatal("Could not create .sef file!");
}
```

One of the most important part of creating .sef files is to get keys from this method it will simply allow the function to read and parse data from files in this case .pem and the .key
```go
var keys, GKErr = Sef.GetKeys("security/"); //*keys include aes encryption key and nonce also []error the slice of errors to handle

if (len(GKErr) != 0) {
  log.Fatal("Could not read security keys!");
}
```

Another part of the program is to encrypt your env in this case to get values from .env file and parse them into aes encrypted file
```go
var ECErr = keys.EncryptENV(values); //[]error

if (len(ECErr) != 0 ){
  log.Fatal("Could not encrypt .env file!")
}
```

You probably wonder ok, but how do I actually get decoded version? Well before we do that we need to get pointer of defined class that parses keys and security together!
```go
var sef *Sef.SefGetters = Sef.DefineSefGetters(keys, "security/"); //&SefGetters{keys *keys; dotenvLocation string;} 
```

Now it's time to decode some values of the encrypted data is not named but listed so we gotta specify the index of what we want. .sef file is as sorted as .env so dont worry that, It's still better to keep your .env file but outside the deployment!
```go
var data, GErr = sef.Get(1); //[]byte of decrypted data and []error

if (len(GErr) != 0){
  log.Fatal("Could not get value");
}

//Print string of decoded data
fmt.Println(string(data));
```

**Keep in mind that after creating and encrypting your .env file you can simply remove it if no updates**

# Adding the package to golang

```sh
go mod init <main directory name>;
go get github.com/DOMIN1310/Sef;
#Add the package to ur main.go file and use it
go mod tidy;
```
Happy coding!
