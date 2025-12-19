package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"io"

	"crypto/ecdsa"
	"crypto/x509"

	"database/sql"

	"encoding/json"
	"encoding/pem"
	"encoding/hex"
	
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



type CredentialSubject struct {
	ID                         string   `json:"id"`
	Identifier                 string   `json:"identifier"`
	EduPersonScopedAffiliation []string `json:"eduPersonScopedAffiliation"`
}

type Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
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
	// Get the email from the session
	emailValue := session.Get("email")
	if emailValue == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	email, ok := emailValue.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid email type in session"})
		return
	}

	// The email is part of the UPC
	if !strings.HasSuffix(email, "@estudiantat.upc.edu") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email is not a UPC student email", "email": email})
		return
	}

	// Get the DID from the form
	did := c.PostForm("did")
	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DID is required"})
		return
	}

	// Insert into DB
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


func getVC(c *gin.Context) {
	// Struct from the body
    var body struct {
        Iss   string `json:"iss"`
        Proof struct {
            Message   string `json:"message"`
            Signature string `json:"signature"`
            Address   string `json:"address"`
        } `json:"proof"`
    }

	// Ensure the posted content contains the expected body
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json", "details": err.Error()})
        return
    }

	// If any of the contents is empty, return error
    if body.Iss == "" || body.Proof.Message == "" || body.Proof.Signature == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "iss, proof.message and proof.signature are required"})
        return
    }

	// The DID must be a did:ethr type
    if !strings.HasPrefix(body.Iss, "did:ethr:") {
        c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported DID method (expect did:ethr:...)"})
        return
    }

    // Normalize DID address & lowercase for comparison
    didAddr := strings.TrimPrefix(body.Iss, "did:ethr:")
    if !strings.HasPrefix(didAddr, "0x") {
        didAddr = "0x" + didAddr
    }
    didAddr = strings.ToLower(didAddr)

    // Verify signature
    ok, recoveredAddr, err := verifyEthereumSignature(body.Proof.Message, body.Proof.Signature)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification error"})
        return
    }
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "signature verification failed"})
        return
    }

    // Logging the address
    log.Printf("getVC: DID=%s recoveredAddr=%s", didAddr, recoveredAddr)

    if strings.ToLower(recoveredAddr) != strings.ToLower(didAddr) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "recovered address does not match DID address", "did": didAddr, "recovered": recoveredAddr})
        return
    }

    iss := body.Iss

    // Find user by DID on the database
    var username string
    err = db.QueryRow("SELECT username FROM users WHERE did = $1 and issued = false", iss).Scan(&username)
    if err != nil {
        if err == sql.ErrNoRows {
            // DID not registered
            c.JSON(http.StatusNotFound, gin.H{"error": "did not found in users table", "did": iss})
            return
        }
        // other DB errors
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

	err = db.QueryRow("UPDATE users SET issued = true WHERE did = $1 RETURNING username", iss).Scan(&username)
    if err != nil {
        if err == sql.ErrNoRows {
            // DID not registered
            c.JSON(http.StatusNotFound, gin.H{"error": "did not found in users table", "did": iss})
            return
        }
        // other DB errors
        log.Printf("getVC: DB query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed", "details": err.Error()})
        return
    }
	

    log.Printf("getVC: issued for user=%s did=%s", username, iss)

	// Return the VC
    c.JSON(http.StatusOK, gin.H{
        "format":     "jwt_vc_json",
        "credential": jwtVC,
    })
}


func getProof(c *gin.Context) {

	// Post must have the VC JWT
	jwtString := c.PostForm("JWT")
	if jwtString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'JWT' in POST form data"})
		return
	}

	// Post must have the public key from the user
	publicKey := c.PostForm("publicKey")
	if publicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'publicKey' in POST form data"})
		return
	}

	// Post must have the DID address
	address := c.PostForm("address")
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'address' in POST form data"})
		return
	}

	// Post must have the user public key
	processID:= c.PostForm("processId")
	if processID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'processId' in POST form data"})
		return
	}

	// Decode the process ID
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

	// Authenticate that the VC was issued by the right Issuer
	IssuerPubKey := pubKey
	VC, err := VerifyJWTAndReturnPayload(jwtString, IssuerPubKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired JWT"})
		return
	}

	// Create the census origin of the CSP
	origin := types.CensusOriginCSPEdDSABLS12377
	seed := []byte(os.Getenv("CSP_SEED"))
	csp, err := csp.New(origin, seed)
	if err != nil {
		panic(fmt.Sprintf("failed to create CSP: %v", err))
	}

	// Check that the user is part of the specific census 
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

	// Generate the proof for the user and process
	proof, err := csp.GenerateProof(pid, addr)
	
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}
	fmt.Println("Voter address: ", addr)

	// Verify that the proof was generated correctly
	if err := csp.VerifyProof(proof); err != nil {
		panic(fmt.Sprintf("failed to verify proof: %v", err))
	}

	fmt.Println("Census proof verified successfully for ")

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
