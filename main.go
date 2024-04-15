package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	supa "github.com/nedpals/supabase-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Note struct {
	ID          uint      `gorm:"primaryKey"`
	Title       string    `gorm:"not null"`
	Description string    `gorm:"not null"`
	CreatedBy   string    `gorm:"not null"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

type NewNoteRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	CreatedBy   string `json:"created_by"`
}
type Claims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}
type User struct {
	ID       uint   `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserID struct {
	UserID string `json:"userId"`
}

var db *gorm.DB
var supabase *supa.Client

func main() {

	/*database set-up*/
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	/* Read environment variables*/
	supabaseUrl := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	databaseUrl := os.Getenv("DATABASE_URL")

	supabase = supa.CreateClient(supabaseUrl, supabaseKey)

	var err error

	db, err = gorm.Open(postgres.Open(databaseUrl), &gorm.Config{})

	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}

	if err != nil {
		log.Fatal("Error setting the RLS policy:", err)
	}

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Post("/note", CreateNote)
	r.Get("/notes", GetAllNote)
	r.Get("/notes/{id}", GetNote)
	r.Put("/notes/{id}", UpdateNote)
	r.Delete("/notes/{id}", DeleteNote)

	log.Println("Starting server on :8080...")

	http.ListenAndServe(":8080", r)

}
func GetAllNote(w http.ResponseWriter, r *http.Request) {

	tokenString := jwtauth.TokenFromHeader(r)
	fmt.Println(tokenString)
	if tokenString == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	UserID, err := decodeJWTToken(tokenString)

	if err != nil {

		http.Error(w, fmt.Sprintf("Failed to decode JWT token: %v", err), http.StatusUnauthorized)
		return

	}

	uuidFromString := uuid.NewSHA1(uuid.NameSpaceOID, []byte(UserID))

	Yes := setRLS(uuidFromString.String())

	fmt.Println(Yes, "Yes")

	var notes []Note

	err = db.Find(&notes).Error

	if err != nil {

		http.Error(w, fmt.Sprintf("Failed to fetch notes: %v", err), http.StatusInternalServerError)

		return

	}

	No := unsetRLS()

	fmt.Println(No, "No")

	render.JSON(w, r, notes)
}

func CreateNote(w http.ResponseWriter, r *http.Request) {

	tokenString := jwtauth.TokenFromHeader(r)
	fmt.Println(tokenString)
	if tokenString == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	UserID, err := decodeJWTToken(tokenString)

	fmt.Println(UserID, "user_id")

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JWT token: %v", err), http.StatusUnauthorized)
		return
	}

	uuidFromString := uuid.NewSHA1(uuid.NameSpaceOID, []byte(UserID))

	Yes := setRLS(uuidFromString.String())
	fmt.Println(Yes, "Yes")

	var req NewNoteRequest

	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, map[string]string{"error": "Invalid request payload"})
		return
	}

	note := Note{
		Title:       req.Title,
		Description: req.Description,
		CreatedBy:   uuidFromString.String(),
	}

	result := db.Create(&note)

	if result.Error != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, map[string]string{"error": "Failed to create note"})
		return
	}

	No := unsetRLS()

	fmt.Println(No)

	render.Status(r, http.StatusCreated)
	render.JSON(w, r, note)

}

func GetNote(w http.ResponseWriter, r *http.Request) {

	tokenString := jwtauth.TokenFromHeader(r)
	fmt.Println(tokenString)
	if tokenString == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	UserID, err := decodeJWTToken(tokenString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JWT token: %v", err), http.StatusUnauthorized)
		return
	}

	noteIDStr := chi.URLParam(r, "id")
	noteID, err := strconv.ParseUint(noteIDStr, 10, 64)

	fmt.Println(noteIDStr, "noteIDStr")
	fmt.Println(noteID, "noteID")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse note ID: %v", err), http.StatusBadRequest)
		return
	}

	noteIDUint := uint(noteID)

	uuidFromString := uuid.NewSHA1(uuid.NameSpaceOID, []byte(UserID))

	Yes := setRLS(uuidFromString.String())

	fmt.Println(Yes, "Yes")

	notes, err := GetNotesByNoteID(noteIDUint)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get notes: %v", err), http.StatusInternalServerError)
		return
	}

	No := unsetRLS()

	fmt.Println(No, "No")

	render.JSON(w, r, notes)
}

func UpdateNote(w http.ResponseWriter, r *http.Request) {

	tokenString := jwtauth.TokenFromHeader(r)
	fmt.Println(tokenString)
	if tokenString == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	UserID, err := decodeJWTToken(tokenString)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JWT token: %v", err), http.StatusUnauthorized)
		return
	}

	noteIDStr := chi.URLParam(r, "id")

	noteID, err := strconv.ParseUint(noteIDStr, 10, 64)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse note ID: %v", err), http.StatusBadRequest)
		return
	}

	noteIDUint := uint(noteID)

	fmt.Println(UserID, "UserID")

	fmt.Println(noteIDUint, "noteIDUint")

	uuidFromString := uuid.NewSHA1(uuid.NameSpaceOID, []byte(UserID))

	fmt.Println(uuidFromString, "uuidFromString")

	Yes := setRLS(uuidFromString.String())

	fmt.Println(Yes, "Yes")

	var req NewNoteRequest

	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, map[string]string{"error": "Invalid request payload"})
		return
	}

	var existingNote Note
	if err := db.Where("id = ?", noteIDUint).First(&existingNote).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to find note with ID %d: %v", noteIDUint, err), http.StatusNotFound)
		return
	}

	existingNote.Title = req.Title
	existingNote.Description = req.Description

	if err := db.Save(&existingNote).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to update note: %v", err), http.StatusInternalServerError)
		return
	}

	No := unsetRLS()

	fmt.Println(No, "No")

	render.JSON(w, r, existingNote)
}

func DeleteNote(w http.ResponseWriter, r *http.Request) {

	tokenString := jwtauth.TokenFromHeader(r)
	fmt.Println(tokenString)
	if tokenString == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	UserID, err := decodeJWTToken(tokenString)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JWT token: %v", err), http.StatusUnauthorized)
		return
	}

	noteIDStr := chi.URLParam(r, "id")

	noteID, err := strconv.ParseUint(noteIDStr, 10, 64)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse note ID: %v", err), http.StatusBadRequest)
		return
	}

	noteIDUint := uint(noteID)

	uuidFromString := uuid.NewSHA1(uuid.NameSpaceOID, []byte(UserID))

	fmt.Println(uuidFromString, "uuidFromString")

	Yes := setRLS(uuidFromString.String())

	fmt.Println(Yes, "Yes")

	var existingNote Note

	if err := db.Where("id = ?", noteIDUint).First(&existingNote).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to find note with ID %d: %v", noteIDUint, err), http.StatusNotFound)
		return
	}

	if err := db.Delete(&existingNote).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete note: %v", err), http.StatusInternalServerError)
		return
	}

	No := unsetRLS()

	fmt.Println(No, "No")

	render.JSON(w, r, map[string]string{"message": "Note deleted successfully"})
}

func decodeJWTToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("brYTIshRfsA1JeYA5wOc2lolCxcoml1SgXxCNoYqYRU="), nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}
	ID, err := extractUserIDFromJWTToken(token)
	if err != nil {
		return "", fmt.Errorf("failed to extract userId from token: %v", err)
	}

	return ID, nil
}
func extractUserIDFromJWTToken(token *jwt.Token) (string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	userIDClaim, ok := claims["user_id"]
	if !ok {
		return "", errors.New("user_id not found in token claims")
	}

	switch userID := userIDClaim.(type) {
	case float64:
		return strconv.FormatUint(uint64(userID), 10), nil
	case uint:
		return strconv.FormatUint(uint64(userID), 10), nil
	default:
		return "", errors.New("unexpected type for user_id")
	}
}
func setRLS(userID string) error {
	query := fmt.Sprintf(`SELECT set_config('request.jwt.claims', '{"sub": "%s"}', false)`, userID)
	fmt.Println(userID, "set Config")
	if err := db.Exec(query).Error; err != nil {
		return err
	}
	return nil
}
func unsetRLS() error {
	query := "RESET request.jwt.claims.sub"
	if err := db.Exec(query).Error; err != nil {
		return err
	}
	return nil
}
func GetNotesByNoteID(noteID uint) ([]Note, error) {
	var notes []Note
	err := db.Where("id = ?", noteID).Find(&notes).Error
	if err != nil {
		return nil, err
	}
	return notes, nil
}
func extractTokenFromHeader(r *http.Request) string {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return ""
	}
	tokenParts := strings.Split(authorizationHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return ""
	}

	return tokenParts[1]
}
