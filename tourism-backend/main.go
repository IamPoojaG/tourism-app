package main

import (
  "net/http"
  "time"

  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v5"
  "golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("secret_key")

type User struct {
  Email string `json:"email"`
  Password string `"json:"password"`
}

var users = map[string]string{} // temp storage
func main() {
  r := gin.Default()

  r.POST("/register",Register)
  r.POST("/login",Login)

  auth :=r.Group("/")
  auth.Use(AuthMiddleware())
  auth.GET("/dashboard",Dashboard)

  r.Run(":8080")
}

func Register(c *gin.Context) {
  var user User
  c.BindJSON(&user)

  hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password),bcrypt.DefaultCost)
  users[user.Email] = string(hash)

  c.JSON(http.StatusOK, gin.H{"message": "Registered successfully"})

}

func Login(c *gin.Context){
  var user User
  c.BindJSON(&user)

  stored, ok := users[user.Email]
  if !ok {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
    return
  }

  err := bcrypt.CompareHashAndPassword([]byte(stored),[]byte(user.Password))
  if err != nil {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
    return
  }

  token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
    "email": user.Email,
    "exp": time.Now().Add(time.Hour * 24).Unix(),
  })

  tokenString, _ := token.SignedString(jwtKey)

  c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func Dashboard(c *gin.Context) {
  c.JSON(http.StatusOK, gin.H{"message": "Welcome to Tourism Dashboard"})
}

func AuthMiddleware() gin.HandlerFunc {
  return func(c *gin.Context) {
    tokenStr := c.GetHeader("Authorization")

    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{},error){
      return jwtKey, nil
    })
    
    if err != nil || !token.Valid {
      c.JSON(http.StatusUnauthorized, gin.H{"error": "Unathorized"})
      c.Abort()
      return
    }
    c.Next()
  }
}