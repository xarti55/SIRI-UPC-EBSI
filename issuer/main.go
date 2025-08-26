package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"encoding/json"
	_ "github.com/lib/pq"
	"github.com/gin-gonic/gin"
)

type CredentialSubject struct {
    ID                         string   `json:"id"`
    Identifier                 string   `json:"identifier"`
    EduPersonScopedAffiliation []string `json:"eduPersonScopedAffiliation"`
}

type CredentialWrapper struct {
    CredentialSubject CredentialSubject `json:"credentialSubject"`
}


var db *sql.DB
var privKey *ecdsa.PrivateKey 
var pubKey *ecdsa.PublicKey 

//Get the private key from the enviroment
func getPrivateKey(){
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

//Get the public key from the enviroment
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



func verifySignature ( data CredentialWrapper, sigBytes []byte) (bool, error) {
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
	var req CredentialWrapper

	//The JSON sent wasn't complient with the schema
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	//Turn the json into bytes (later signature)
	jsonBytes, err := json.Marshal(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal JSON: " + err.Error()})
		return
	}

	//Check if the user exists
	var exists bool
	if err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", req.CredentialSubject.Identifier).Scan(&exists); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error3": err.Error()})
		return
	}
	
	//Sign the hash of the message
	msgHash := sha256.Sum256([]byte(jsonBytes))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msgHash[:])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign error: " + err.Error()})
		return
	}
	signature := append(r.Bytes(), s.Bytes()...)
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	//Verify (test)
	verified, verr := verifySignature(req, signature)
	if verr != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification error: " + verr.Error()})
		return
	}

	if exists {
		c.JSON(http.StatusOK, gin.H{
			"user":         req.CredentialSubject.Identifier,
			"exists":       true,
			"signature":    sigB64,
			"verification": verified,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"user":   req.CredentialSubject.Identifier,
			"exists": false,
		})
	}
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
	

	router := gin.Default()

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

	router.POST("/getVC", getVC)
	router.Run(":8080")
}
