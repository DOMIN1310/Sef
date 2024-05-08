//Package
package Sef

//Imports
import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path"
	"strings"
)

//Getter
func genRandomBytes(long int) ([]byte, error) {
	var bytes []byte = make([]byte, long);
	var _, RErr = rand.Read(bytes);
	if (RErr != nil) {
		return nil, errors.New("Error: " + RErr.Error());
	}
	return bytes, nil;
}

//Getter
func getPath(file ...string) string {
	return path.Join(file[0], file[1]);
}

//Constructor
func GenerateSecurity(securityDirPath string) []error {
	//Variables
	var err []error;
	var key, GErr = genRandomBytes(32);
	if (GErr != nil) { err = append(err, errors.New("Error: " + GErr.Error())); }
	var AESKey *pem.Block = 
		&pem.Block{
			Type: "AES KEY",
			Bytes: key,
		}
	var keypath = getPath(securityDirPath, ".pem");
	//Create Security
	var dotpem, CErr = os.Create(keypath);
	if (CErr != nil) { err = append(err, errors.New("Could not create file ensure provided path was correct: " + CErr.Error())); }
	defer dotpem.Close();
	var EErr = pem.Encode(dotpem, AESKey);
	if (EErr != nil){ err = append(err, errors.New("Could not write to file: " + EErr.Error())); }
	var nonce, GErr2 = genRandomBytes(12);
	if (GErr2 != nil) { err = append(err, errors.New("Error: " + GErr2.Error())); }
	var noncepath string = getPath(securityDirPath, ".key");
	var dotkey, CErr2 = os.Create(noncepath);
	if (CErr2 != nil) { err = append(err, errors.New("Could not create file ensure provided path was correct: " + CErr2.Error())); }
	var _, WErr = dotkey.Write([]byte(base64.StdEncoding.EncodeToString(nonce)));
	if (WErr != nil) {err = append(err, errors.New("Could not write the file error: " + WErr.Error()));}
	return err;
}

//Constructor
type Keys struct {
	key []byte;
	nonce []byte;
}

//Getter
func GetKeys(securityPath string) (*Keys, []error) {
	//Variables
	var err []error;
	//Decoder && Checker
	var keyBuffer, RFErr = os.ReadFile(path.Join(securityPath, ".pem"));
	if (RFErr != nil) { err = append(err, errors.New("Could not get keys: " + RFErr.Error())); }
	var block, _ = pem.Decode(keyBuffer);
	var key []byte = block.Bytes;
	switch (len(key)) {
	case 16, 24, 32:
		break;
	default:
		return nil, err;
	}
	//Reader
	var nonceb64, RFErr2 = os.ReadFile(path.Join(securityPath + ".key"));
	if (RFErr2 != nil) { err = append(err, errors.New("Could not get nonce: " + RFErr2.Error())); }
	var nonce, _ = base64.StdEncoding.DecodeString(string(nonceb64));
	return &Keys{
		key: key,
		nonce: nonce,
	}, nil;
}

//Getter
func readENV(envFile string) ([]string, error){
	//Variables
	var err error;
	var env []string;
	var file, OErr = os.Open(path.Join(envFile, ".env"));
	if (OErr != nil) { err = errors.New("Error: " + OErr.Error()); }
	defer file.Close();
	//Reader
	var scanner = bufio.NewScanner(file);
	for scanner.Scan() {
		var splitted []string = strings.Split(scanner.Text(), "=");
		env = append(env, splitted[1]);
	}
	return env, err;
}

//Constructor
func CreateSef(envFile string, distLocation string) ([]string, []error) {
	//Variables
	var err []error;
	var env, EnvErr = readENV(envFile);
	if (EnvErr != nil) { err = append(err, errors.New("Could not read ENV file ensure the provided path was correct")); }
	var sefLocation = path.Join(distLocation + ".sef");
	//Creator
	var file, CErr = os.Create(sefLocation);
	if (CErr != nil) { err = append(err, errors.New("Error: " + CErr.Error())); }
	defer file.Close();
	env = append(env, sefLocation);
	return env, err;
}

//Constructor
func (k Keys) EncryptENV(values []string) []error {
	var err []error;
	//cipher
	var block, NCErr = aes.NewCipher(k.key);
	if (NCErr != nil) {err = append(err, errors.New("Error: "+ NCErr.Error())); }
	//Encryption
	var gcm, GCMErr = cipher.NewGCM(block);
	if (GCMErr != nil) {err = append(err, errors.New("Error: "+ GCMErr.Error())); }
	//Encrypt
	var file strings.Builder;
	for row := range values {
		if (len(values)-1 == row) { break; }
		var ciphertext string = base64.StdEncoding.EncodeToString(gcm.Seal(nil, k.nonce, []byte(values[row]), nil));
		file.WriteString(ciphertext + "\n");
	}
	//Writer
	var WErr = os.WriteFile(values[len(values)-1], []byte(file.String()), 0666);
	if (WErr != nil) { err = append(err, errors.New("Error: "+ WErr.Error())); }
	return err;
}

//Constructor
type SefGetters struct {
	keys Keys;
	location string;
}

//Setter
func DefineSefGetters(keys *Keys, location string) *SefGetters {
	return &SefGetters{
		keys: *keys,
		location: location,
	};
}

//Getter
func readSef(location string) ([]string, error) {
	//Variables
	var err error;
	var data []string;
	var file, OErr = os.Open(path.Join(location + ".sef"));
	if (OErr != nil) { err = errors.New("Could not find .sef file in provided location ensure the path is correct!"); }
	//Reader
	var scanner *bufio.Scanner =	bufio.NewScanner(file);
	for scanner.Scan() {
		data = append(data, scanner.Text());
	}
	return data, err;
}

//Getter
func (sg SefGetters) Get(index int) ([]byte, []error) {
	//Variables
	var err []error;
	var b64, RSefError = readSef(sg.location)
	if (RSefError != nil) { err = append(err, errors.New("Error: " + RSefError.Error() )); }
	var wanted []byte;
	if (len(b64) < index) {
		err = append(err, errors.New("Error: Could not find the value u were looking for."));
	} else {
		var decoded, DErr = base64.StdEncoding.DecodeString(b64[index]);
		if (DErr != nil) { err = append(err, errors.New("Error: " + DErr.Error())); }
		wanted = decoded;
	}
	//Cipher
	var block, NPErr = aes.NewCipher(sg.keys.key);
	if (NPErr != nil) { err = append(err, errors.New("Errors: " + NPErr.Error())); }
	//GCM
	var gcm, gcmErr = cipher.NewGCM(block);
	if (gcmErr != nil) { err = append(err, errors.New("Errors: " + gcmErr.Error())); }
	//Decoder
	var data, AesDErr = gcm.Open(nil, sg.keys.nonce, wanted, nil);
	if (AesDErr != nil) { err = append(err, errors.New("Errors: " + AesDErr.Error())); }
	return data, err;
}