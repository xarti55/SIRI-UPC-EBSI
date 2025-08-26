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

	_ "github.com/lib/pq"
	"github.com/gin-gonic/gin"
)

type UserRequest struct {
	User string `json:"user"`
}

var db *sql.DB

func parsePublicKey() (*ecdsa.PublicKey, error) {
	pkEnv := strings.ReplaceAll(os.Getenv("PUBLIC_KEY"), `\n`, "\n")
	if block, _ := pem.Decode([]byte(pkEnv)); block != nil {
		pubI, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := pubI.(*ecdsa.PublicKey)
		if !ok {
			return nil, err
		}
		return pub, nil
	}
	
	raw, err := base64.StdEncoding.DecodeString(pkEnv)
	if err != nil {
		return nil, err
	}
	pubI, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}
	pub, ok := pubI.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}
	return pub, nil
}

func verifySignature(username string, sigBytes []byte) (bool, error) {
	pub, err := parsePublicKey()
	if err != nil {
		return false, err
	}
	half := len(sigBytes) / 2
	if half == 0 {
		return false, nil
	}
	r := new(big.Int).SetBytes(sigBytes[:half])
	s := new(big.Int).SetBytes(sigBytes[half:])
	digest := sha256.Sum256([]byte(username))
	ok := ecdsa.Verify(pub, digest[:], r, s)
	return ok, nil
}

func getVC(c *gin.Context) {
	var req UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var exists bool
	if err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", req.User).Scan(&exists); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	privateKeyPEM := strings.ReplaceAll(os.Getenv("PRIVATE_KEY"), `\n`, "\n")
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse PRIVATE_KEY PEM block"})
		return
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse EC private key: " + err.Error()})
		return
	}

	msgHash := sha256.Sum256([]byte(req.User))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msgHash[:])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign error: " + err.Error()})
		return
	}
	signature := append(r.Bytes(), s.Bytes()...)
	sigB64 := base64.StdEncoding.EncodeToString(signature)


	verified, verr := verifySignature(req.User, signature)
	if verr != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification error: " + verr.Error()})
		return
	}

	if exists {
		c.JSON(http.StatusOK, gin.H{
			"user":         req.User,
			"exists":       true,
			"signature":    sigB64,
			"verification": verified,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"user":   req.User,
			"exists": false,
		})
	}
}

func main() {
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

	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello"})
	})


	//testing
	router.GET("/getusers", func(c *gin.Context) {
		rows, err := db.Query("SELECT username FROM users")
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
