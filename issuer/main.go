package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	_ "github.com/lib/pq"
	"github.com/skip2/go-qrcode"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
)



var googleOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_KEY"),
	RedirectURL:  os.Getenv("ENDPOINT_URL")  + "/auth/google/callback",
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
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

var db *sql.DB
var privKey *ecdsa.PrivateKey
var pubKey *ecdsa.PublicKey

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

	if err := token.Set(jwt.IssuerKey, "did:ebsi:UPCID"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.AudienceKey, "https://your-client-app.example.com"); err != nil { // replace with your client ID or URL
		return "", err
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(10 * time.Minute)); err != nil { // short-lived token
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
		"issuer":            "did:ebsi:UPCID",
		"issuanceDate":      now.UTC().Format(time.RFC3339Nano),
		"credentialSubject": subject,
		"credentialStatus": map[string]interface{}{
			"id":   "https://your-server.com/status/123",  
			"type": "CredentialStatusList2021",            
		},
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
	if err := token.Set(jwt.ExpirationKey, now.Add(24*time.Hour)); err != nil {
		return "", err
	}
	if err := token.Set(jwt.IssuerKey, "did:ebsi:UPCID"); err != nil {
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

	//Check JSON is complient with the expected schema
	var req IncomingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("Binding error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	//Decode the JWT (contains DID)
	payloadJSON, err := decodeJWTPayload(req.Proof.JWT)
	if err != nil {
		fmt.Println("Error decoding payload:", err)
		return
	}

	//Get the DID
	var payloadMap map[string]interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &payloadMap); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	iss, ok := payloadMap["iss"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issuer in payload"})
		return
	}

	//Check if the user exists
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE did = $1", iss).Scan(&username); if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error3": err.Error()})
		return
	}

	//Issue the VC
	jwtVC, err := issueVC(username,iss)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fmt.Println("Returning VC JWT to wallet:")
	fmt.Println(jwtVC)

	c.JSON(http.StatusOK, gin.H{
		"format":    "jwt_vc_json",
		"credential": jwtVC,
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

	//testing
	router.GET("/getusers", func(c *gin.Context) {
		rows, err := db.Query("SELECT username FROM users WHERE username IS NOT NULL")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var usernames []string
		for rows.Next() {
			var username string
			if err := rows.Scan(&username); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			usernames = append(usernames, username)
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": usernames})
	})


	router.GET("/credential-offer", func(c *gin.Context) {
		preAuthJWT, err := generatePreAuthCodeJWT() 
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate pre-authorized code"})
			return
		}

		credentialOffer := map[string]interface{}{
				"credential_issuer": os.Getenv("ENDPOINT_URL") ,
				"credentials": []map[string]interface{}{
					{
						"format": "jwt_vc",
						"types": []string{"VerifiableCredential", "VerifiableEducationalID"},
					},
				},
				"grants": map[string]interface{}{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
						"pre-authorized_code": preAuthJWT,
						"user_pin_required":   false,
					},
				},
				"trust_framework": map[string]interface{}{
					"name": "ebsi",
					"type": "Accreditation",
					"uri":  "TIR link towards accreditation",
				},
		}

		c.JSON(http.StatusOK, credentialOffer)
	})


	router.GET("/qr", func(c *gin.Context) {
		offerURL := "openid-credential-offer://?credential_offer_uri=" + os.Getenv("ENDPOINT_URL") + "/credential-offer"

		png, err := qrcode.Encode(offerURL, qrcode.Medium, 256)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR"})
			return
		}

		c.Header("Content-Type", "image/png")
		c.Writer.Write(png)
	})


	

	router.POST("/token", func(c *gin.Context) {
		grantType := c.PostForm("grant_type")
		preAuthCode := c.PostForm("pre-authorized_code")

		if grantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
			return
		}

		_, err := jwt.Parse([]byte(preAuthCode), jwt.WithKey(jwa.ES256, pubKey))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant", "detail": err.Error()})
			return
		}

		accessToken := "access-token-xyz" 
		cNonce := "random-nonce-abc"

		c.JSON(http.StatusOK, gin.H{
			"access_token":       accessToken,
			"token_type":         "bearer",
			"expires_in":         600,
			"c_nonce":            cNonce,
			"c_nonce_expires_in": 600,
		})
	})

	//https://openid.net/specs/openid-connect-discovery-1_0.html
	//issuer: URL using the https scheme with no query or fragment components
	//token_endpoint: URL of the OP's OAuth 2.0 Token Endpoint
	router.GET("/.well-known/oauth-authorization-server", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, gin.H{
			"issuer":                             os.Getenv("ENDPOINT_URL") ,
			"token_endpoint":                     os.Getenv("ENDPOINT_URL") + "/token",
			"grant_types_supported":              []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"response_types_supported":           []string{"token"},
			"scopes_supported":                   []string{"openid", "vc_credential"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"authorization_response_iss_parameter_supported": true,
			"require_pushed_authorization_requests": false,
		})
	})

	router.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, gin.H{
			"issuer":         os.Getenv("ENDPOINT_URL") ,
			"token_endpoint": os.Getenv("ENDPOINT_URL")  + "/token",
			"grant_types_supported": []string{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code",
			},
			"response_types_supported": []string{"token"},
			"scopes_supported":         []string{"openid", "vc_credential"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	})

	//https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
	//credential_issuer: credential issuer identifier
	//authorization_server:
	//credential_endpoint: URL of the Credential Issuer's Credential Endpoint

	router.GET("/.well-known/openid-credential-issuer", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, gin.H{
			"credential_issuer":    os.Getenv("ENDPOINT_URL") ,
			"authorization_server": os.Getenv("ENDPOINT_URL") ,
			"credential_endpoint":  os.Getenv("ENDPOINT_URL") + "/getVC",
			"credentials_supported": []map[string]interface{}{
				{
					"format": "jwt_vc",
					"types":  []string{"VerifiableCredential", "VerifiableEducationalID"},
				},
			},
			"grant_types_supported": []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"user_pin_required":     false,
		})
	})



	router.GET("/auth/google", func(c *gin.Context) {
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
			<form method="POST" action="/register-did">
			<label for="did">Enter your DID:</label>
			<input type="text" id="did" name="did" required />
			<button type="submit">Submit DID</button>
			</form>
		</body>
		</html>
		`)
	})


	




	router.POST("/getVC", getVC)
	router.POST("/register-did", registerDID)
	err = router.RunTLS(":443", "/cert.pem", "/key.pem")
	if err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}

}
