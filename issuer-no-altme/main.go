package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"errors"
	"time"
	"io"

	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"

	"database/sql"

	"encoding/json"
	"encoding/pem"
	"encoding/base64"
	"encoding/hex"

	"math/big"
	_ "math/rand"
	
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	_ "github.com/lib/pq"


	"github.com/skip2/go-qrcode"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	
	"github.com/vocdoni/davinci-node/crypto/csp"
	"github.com/vocdoni/davinci-node/types"
	"github.com/vocdoni/davinci-node/util"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)


var googleOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_KEY"),
	RedirectURL:  os.Getenv("ENDPOINT_URL")  + "/auth/google/callback",
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

type JWK struct {
    Kty string `json:"kty"`
    Crv string `json:"crv"`
    X   string `json:"x"`
    Y   string `json:"y"`
}

type VerificationMethod struct {
    ID           string `json:"id"`
    Type         string `json:"type"`
    Controller   string `json:"controller"`
    PublicKeyJwk *JWK   `json:"publicKeyJwk,omitempty"`
}

type DIDDocument struct {
    ID                 string               `json:"id"`
    VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

type RegisterPayload struct {
    DID string `json:"did"`
}


type CredentialSubject struct {
	ID                         string   `json:"id"`
	Identifier                 string   `json:"identifier"`
	EduPersonScopedAffiliation []string `json:"eduPersonScopedAffiliation"`
}

type CredentialWrapper struct {
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

type Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

type IncomingRequest struct {
	Proof  Proof    `json:"proof"`
	Types  []string `json:"types"`
	Format string   `json:"format"`
}

type DIDResolutionResponse struct {
    DIDDocument DIDDocument `json:"didDocument"`
}

type VC struct {
	Context           []string          `json:"@context"`
	CredentialStatus  map[string]string `json:"credentialStatus"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	IssuanceDate      string            `json:"issuanceDate"`
	Issuer            string            `json:"issuer"`
	Type              []string          `json:"type"`
}

type VerifiedJWT struct {
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
	Jti string `json:"jti"`
	Nbf int64  `json:"nbf"`
	Sub string `json:"sub"`
	VC  VC     `json:"vc"`
}

var db *sql.DB
var privKey *ecdsa.PrivateKey
var pubKey *ecdsa.PublicKey



// helper: verify Ethereum personal_sign signature over message
// returns (true, recoveredAddressHex, nil) on success
func verifyEthereumSignature(message string, sigHex string) (bool, string, error) {
    // strip 0x
    if strings.HasPrefix(sigHex, "0x") {
        sigHex = sigHex[2:]
    }

    sig, err := hex.DecodeString(sigHex)
    if err != nil {
        return false, "", fmt.Errorf("invalid signature hex: %w", err)
    }
    if len(sig) != 65 {
        return false, "", fmt.Errorf("signature length must be 65 bytes")
    }

    // Adjust V if needed: many signers return v as 27/28, go-ethereum expects 0/1
    v := sig[64]
    if v >= 27 {
        sig[64] = v - 27
    }

    // Compute the Ethereum-specific message hash:
    // "\x19Ethereum Signed Message:\n" + len(message) + message
    prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
    msgHash := crypto.Keccak256([]byte(prefixed))

    // Recover public key
    pubKey, err := crypto.SigToPub(msgHash, sig)
    if err != nil {
        return false, "", fmt.Errorf("signature recovery failed: %w", err)
    }

    // Compute address
    recoveredAddr := crypto.PubkeyToAddress(*pubKey).Hex() // e.g. 0xabc...
    return true, strings.ToLower(recoveredAddr), nil
}



func LoadECDSAPublicKeyFromPEM(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPubKey, nil
}

func VerifyJWTAndReturnPayload(jwtString string, pubKey *ecdsa.PublicKey) (*VerifiedJWT, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithKey(jwa.ES256, pubKey))
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	jsonBuf, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWT token: %w", err)
	}

	var verifiedJWT VerifiedJWT
	if err := json.Unmarshal(jsonBuf, &verifiedJWT); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload into struct: %w", err)
	}

	return &verifiedJWT, nil
}

func decodeBase64URL(data string) ([]byte, error) {
    if pad := len(data) % 4; pad != 0 {
        data += strings.Repeat("=", 4-pad)
    }
    return base64.URLEncoding.DecodeString(data)
}

func getIssuerPublicKey(did string) (string, error) {
	url := "https://api-pilot.ebsi.eu/did-registry/v5/identifiers/" + did

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to resolve Issuer DID: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolver returned %d", resp.StatusCode)
	}

	// Define matching struct for the v5 response
	var result struct {
		VerificationMethod []struct {
			PublicKeyJwk *JWK `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("invalid JSON from resolver: %w", err)
	}

	// Look for a JWK with EC key type
	for _, vm := range result.VerificationMethod {
		if vm.PublicKeyJwk != nil && vm.PublicKeyJwk.Kty == "EC" {
			xBytes, err := decodeBase64URL(vm.PublicKeyJwk.X)
			if err != nil {
				return "", fmt.Errorf("failed to decode x: %w", err)
			}
			yBytes, err := decodeBase64URL(vm.PublicKeyJwk.Y)
			if err != nil {
				return "", fmt.Errorf("failed to decode y: %w", err)
			}

			// Concatenate 0x04 || X || Y (uncompressed EC format)
			pubKey := append([]byte{0x04}, append(xBytes, yBytes...)...)
			return "0x" + hex.EncodeToString(pubKey), nil
		}
	}

	return "", fmt.Errorf("no EC public key found in DID document")
}

func getPublicKeyFromDID(did string) (string, error) {
    url := "https://uniresolver.io/1.0/identifiers/" + did

    resp, err := http.Get(url)
    if err != nil {
        return "", fmt.Errorf("failed to resolve user DID: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("resolver returned %d", resp.StatusCode)
    }

    var result DIDResolutionResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", fmt.Errorf("invalid JSON from resolver: %w", err)
    }

    if len(result.DIDDocument.VerificationMethod) == 0 {
        return "", errors.New("no verification methods found")
    }

    // Use the first verification method with a JWK
    for _, vm := range result.DIDDocument.VerificationMethod {
        if vm.PublicKeyJwk != nil && vm.PublicKeyJwk.Kty == "EC" {
            xBytes, err := decodeBase64URL(vm.PublicKeyJwk.X)
            if err != nil {
                return "", fmt.Errorf("failed to decode x: %w", err)
            }

            yBytes, err := decodeBase64URL(vm.PublicKeyJwk.Y)
            if err != nil {
                return "", fmt.Errorf("failed to decode y: %w", err)
            }

            // Uncompressed EC key format: 0x04 || X || Y
            pubKey := append([]byte{0x04}, append(xBytes, yBytes...)...)
            return "0x" + hex.EncodeToString(pubKey), nil
        }
    }

    return "", errors.New("no supported EC public key found")
}

func decodeJWTPayload(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid token: expected at least 2 parts")
	}

	payload := parts[1]

	// Base64 URL decode
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func generatePreAuthCodeJWT() (string, error) {
	now := time.Now()

	token := jwt.New()

	if err := token.Set(jwt.IssuerKey, "did:ebsi:zwLxYsDTPjsSZCfH9VcUzSA"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.AudienceKey, "https://your-client-app.example.com"); err != nil { 
		return "", err
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(10 * time.Minute)); err != nil { 
		return "", err
	}
	if err := token.Set("nonce", "random-nonce-abc"); err != nil { // or generate a real random nonce
		return "", err
	}
	if err := token.Set(jwt.SubjectKey, "some-subject-identifier"); err != nil {
		return "", err
	}

	// Sign the JWT using your private key and ES256 algorithm
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// Get the private key from the enviroment
func getPrivateKey() {
	privateKeyPEM := strings.ReplaceAll(os.Getenv("PRIVATE_KEY"), `\n`, "\n")
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		log.Fatal("Failed to decode the private key")
	}
	var err error
	privKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse the private key")
	}
}

// Get the public key from the enviroment
func getPublicKey() {
	publicKeyPEM := strings.ReplaceAll(os.Getenv("PUBLIC_KEY"), `\n`, "\n")
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		log.Fatal("Failed to decode the public key")
	}
	pubI, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse the public key")
	}
	var ok bool
	pubKey, ok = pubI.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Public key is not of type *ecdsa.PublicKey")
	}
}

func registerDID(c *gin.Context) {
	session := sessions.Default(c)
	email := session.Get("email")
	if email == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	did := c.PostForm("did")
	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DID is required"})
		return
	}

	// Insert into DB, assuming your users table has "username" and "did"
	_, err := db.Exec("INSERT INTO users (username, did) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET did = EXCLUDED.did", email, did)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB insert failed", "details": err.Error()})
		return
	}

	c.String(http.StatusOK, "DID registered successfully!")
}

func issueVC(username string, DID string) (string, error) {
	subject := CredentialSubject{
		ID:                         DID,
		Identifier:                 username,
		EduPersonScopedAffiliation: []string{username},
	}

	now := time.Now()

	vc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/z5rvJVo9iVGZTqEWVVKNYWyw31FjDWvXhz91qtGo39y44",
		},
		"type":              []string{"VerifiableCredential", "VerifiableEducationalID"},
		"issuer":            "did:ebsi:zwLxYsDTPjsSZCfH9VcUzSA",
		"issuanceDate":      now.UTC().Format(time.RFC3339Nano),
		"credentialSubject": subject,
		
	}

	token := jwt.New()

	if err := token.Set("nbf", now); err != nil {
		return "", err
	}
	if err := token.Set("jti", "urn:uuid:your-unique-id"); err != nil {
		return "", err
	}

	if err := token.Set("vc", vc); err != nil {
		return "", err
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(24*24*time.Hour)); err != nil {
		return "", err
	}
	if err := token.Set(jwt.IssuerKey, "did:ebsi:zwLxYsDTPjsSZCfH9VcUzSA"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.SubjectKey, subject.ID); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func verifySignature(data CredentialWrapper, sigBytes []byte) (bool, error) {
	half := len(sigBytes) / 2
	if half == 0 {
		return false, nil
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return false, nil
	}
	r := new(big.Int).SetBytes(sigBytes[:half])
	s := new(big.Int).SetBytes(sigBytes[half:])
	digest := sha256.Sum256(jsonBytes)
	ok := ecdsa.Verify(pubKey, digest[:], r, s)
	return ok, nil
}

func getVC(c *gin.Context) {
    var body struct {
        Iss   string `json:"iss"`
        Proof struct {
            Message   string `json:"message"`
            Signature string `json:"signature"`
            Address   string `json:"address"`
        } `json:"proof"`
    }

    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json", "details": err.Error()})
        return
    }

    if body.Iss == "" || body.Proof.Message == "" || body.Proof.Signature == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "iss, proof.message and proof.signature are required"})
        return
    }

    if !strings.HasPrefix(body.Iss, "did:ethr:") {
        c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported DID method (expect did:ethr:...)"})
        return
    }

    // normalize DID address & lowercase for comparison
    didAddr := strings.TrimPrefix(body.Iss, "did:ethr:")
    if !strings.HasPrefix(didAddr, "0x") {
        didAddr = "0x" + didAddr
    }
    didAddr = strings.ToLower(didAddr)

    // Verify signature
    ok, recoveredAddr, err := verifyEthereumSignature(body.Proof.Message, body.Proof.Signature)
    if err != nil {
        // include details while debugging - remove or redact in production
        c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification error", "details": err.Error()})
        return
    }
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "signature verification failed"})
        return
    }

    // Log addresses so you can see mismatches in logs / ngrok
    log.Printf("getVC: DID=%s recoveredAddr=%s", didAddr, recoveredAddr)

    if strings.ToLower(recoveredAddr) != strings.ToLower(didAddr) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "recovered address does not match DID address", "did": didAddr, "recovered": recoveredAddr})
        return
    }

    iss := body.Iss

    // Find user by DID
    var username string
    err = db.QueryRow("SELECT username FROM users WHERE did = $1", iss).Scan(&username)
    if err != nil {
        if err == sql.ErrNoRows {
            // DID not registered with your service
            c.JSON(http.StatusNotFound, gin.H{"error": "did not found in users table", "did": iss})
            return
        }
        // other DB error
        log.Printf("getVC: DB query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed", "details": err.Error()})
        return
    }

    // Issue the VC
    jwtVC, err := issueVC(username, iss)
    if err != nil {
        log.Printf("getVC: issueVC error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue VC", "details": err.Error()})
        return
    }

    log.Println("Returning VC JWT to wallet")
    // Optionally redact JWT in logs during production
    log.Printf("getVC: issued for user=%s did=%s", username, iss)

    c.JSON(http.StatusOK, gin.H{
        "format":     "jwt_vc_json",
        "credential": jwtVC,
    })
}


func DIDtoKey(){

}

func getProof(c *gin.Context) {
	jwtString := c.PostForm("JWT")
	if jwtString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'JWT' in POST form data"})
		return
	}

	publicKey := c.PostForm("publicKey")
	if publicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'publicKey' in POST form data"})
		return
	}

	address := c.PostForm("address")
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'address' in POST form data"})
		return
	}

	processID:= c.PostForm("processId")
	if processID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'processId' in POST form data"})
		return
	}

	strPID := util.TrimHex(processID)
	bPID, err := hex.DecodeString(strPID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid process ID"})
		return
	}
	pid := new(types.ProcessID).SetBytes(bPID)
	if !pid.IsValid() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid process ID"})
		return
	}

	IssuerPubKey := pubKey
	VC, err := VerifyJWTAndReturnPayload(jwtString, IssuerPubKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired JWT"})
		return
	}

	origin := types.CensusOriginCSPEdDSABLS12377
	seed := []byte(os.Getenv("CSP_SEED"))
	csp, err := csp.New(origin, seed)
	if err != nil {
		panic(fmt.Sprintf("failed to create CSP: %v", err))
	}


	var username string
	err = db.QueryRow("SELECT * FROM FINE_users WHERE username = $1", VC.VC.CredentialSubject.Identifier).Scan(&username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User is not part of FINE"})
		return
	}

	fmt.Println("User: ", username)
	fmt.Println("Public Key (hex):", publicKey)

	publicKey = strings.TrimPrefix(publicKey, "0x")
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	// Remove the 0x04 prefix (first byte)
	pubKeyBytes = pubKeyBytes[1:]

	// Hash the remaining 64 bytes with Keccak256
	hash := crypto.Keccak256(pubKeyBytes)

	//  Take the last 20 bytes of the hash
	voter := common.BytesToAddress(hash[12:])
	fmt.Println(voter)
	
	addr := common.HexToAddress(address)
	proof, err := csp.GenerateProof(pid, addr)
	
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}
	fmt.Println("VOter address: ", addr)


	if err := csp.VerifyProof(proof); err != nil {
		panic(fmt.Sprintf("failed to verify proof: %v", err))
	}

	fmt.Println("Census proof verified successfully!")

	c.JSON(http.StatusOK, gin.H{
		"proof": proof,
	})
}


func main() {

	//Connect to the DB
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set")
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping DB: %v", err)
	}

	//Load keys
	getPublicKey()
	getPrivateKey()


	//Generate cookies
	router := gin.Default()
	router.Use(cors.Default())
	store := cookie.NewStore([]byte(os.Getenv("COOKIE_PASS"))) 
	router.Use(sessions.Sessions("mysession", store))


	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello"})
	})


	
	router.GET("/issuer/qr", func(c *gin.Context) {
		offerURL := "openid-credential-offer://?credential_offer_uri=" + os.Getenv("ENDPOINT_URL") + "/credential-offer"

		png, err := qrcode.Encode(offerURL, qrcode.Medium, 256)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR"})
			return
		}

		c.Header("Content-Type", "image/png")
		c.Writer.Write(png)
	})

	router.GET("issuer/auth/google", func(c *gin.Context) {
		url := googleOauthConfig.AuthCodeURL("random-state") // TODO: use real state
		c.Redirect(http.StatusFound, url)
	})

	router.GET("/auth/google/callback", func(c *gin.Context) {

		code := c.Query("code")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code"})
			return
		}

		token, err := googleOauthConfig.Exchange(c, code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token exchange failed", "details": err.Error()})
			return
		}

		client := googleOauthConfig.Client(c, token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get userinfo", "details": err.Error()})
			return
		}
		defer resp.Body.Close()

		userinfo, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response", "details": err.Error()})
			return
		}

		// Parse the JSON response
		var data map[string]interface{}
		if err := json.Unmarshal(userinfo, &data); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse userinfo", "details": err.Error()})
			return
		}

		//Check the user is a UPC student
		email := data["email"].(string)
		if !strings.HasSuffix(email, "@estudiantat.upc.edu") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Email is not a UPC student email", "email": email})
			return
		}

		session := sessions.Default(c)
		session.Set("email", email)
		session.Save()

		//Send the user the response so it send the DID
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `
		<html>
		<body>
			<h1>Welcome, ` + email + `</h1>
			<form method="POST" action="/issuer/register-did">
			<label for="did">Enter your DID:</label>
			<input type="text" id="did" name="did" required />
			<button type="submit">Submit DID</button>
			</form>
		</body>
		</html>
		`)
	})

	router.GET("/verifier/root" , func(c *gin.Context){
		eddsaCSP, err := csp.New(types.CensusOriginCSPEdDSABLS12377, []byte(os.Getenv("CSP_SEED")))
		if err != nil {
		 panic(fmt.Sprintf("Root panic"))
		}
		root := eddsaCSP.CensusRoot() // return a custom struct that is json serializable json wrapper
		c.JSON(200, root)
	})

	
	router.POST("/verifier/getProof", getProof)
	router.POST("/issuer/getVC", getVC)
	router.POST("/issuer/register-did", registerDID)
	err = router.Run(":7531")
	if err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}

}
