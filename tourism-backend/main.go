package main
import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	router := gin.Default()

	// CORS Middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	router.POST("/login", func(c *gin.Context) {
		var input LoginInput

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Invalid input",
			})
			return
		}

		// Dummy Authentication
		if input.Email == "admin@gmail.com" && input.Password == "123456" {
			c.JSON(http.StatusOK, gin.H{
				"message": "Login successful",
				"token":   "sample-jwt-token",
			})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid email or password",
		})
	})

	router.Run(":8080")
}