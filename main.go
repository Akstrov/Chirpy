package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// chirp is like a tweet
type chirp struct {
	Body string `json:"body"`
	Id   int    `json:"id"`
}

// user struct
type user struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Token     string `json:"token"`
	Id        int    `json:"id"`
	ExpiresIn int    `json:"expires_in_seconds"`
}

// DB represents the database's path
type DB struct {
	mux  *sync.RWMutex
	path string
}

// DBStructure represents the structure of the database
type DBStructure struct {
	Chirps map[int]chirp `json:"chirps"`
	Users  map[int]user  `json:"users"`
}

// newDB creates a new database in the given path
func newDB(path string) (*DB, error) {
	dbStructure := DBStructure{
		Chirps: make(map[int]chirp),
		Users:  make(map[int]user),
	}
	dat, err := json.MarshalIndent(dbStructure, "", "  ")
	if err != nil {
		return nil, err
	}
	os.WriteFile(path, dat, 0644)
	return &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}, nil
}

func (db *DB) updateUser(id int, sentUser user) (user, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	dbStructure, err := db.loadDB()
	if err != nil {
		return user{}, err
	}
	for k, u := range dbStructure.Users {
		if u.Id == id {
			bytes, err := bcrypt.GenerateFromPassword([]byte(sentUser.Password), bcrypt.DefaultCost)
			if err != nil {
				return user{}, err
			}
			entry := dbStructure.Users[k]
			entry.Email = sentUser.Email
			entry.Password = string(bytes)
			dbStructure.Users[k] = entry
			db.writeDB(dbStructure)
			return user{
				Email: entry.Email,
				Id:    entry.Id,
			}, nil
		}
	}
	return user{}, fmt.Errorf("user not found")
}

func (db *DB) lookupUserByEmail(email string) (user, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	dbStructure, err := db.loadDB()
	if err != nil {
		return user{}, err
	}
	for _, u := range dbStructure.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return user{}, fmt.Errorf("user not found")
}

func (db *DB) createUser(email, password string) (user, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	err := db.ensureDB()
	if err != nil {
		return user{}, err
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		return user{}, err
	}
	id := 0
	for k, u := range dbStructure.Users {
		// check if user already exists
		if u.Email == email {
			return user{}, fmt.Errorf("user already exists")
		}
		if k > id {
			id = k
		}
	}
	id++
	pwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return user{}, nil
	}
	u := user{
		Email:    email,
		Password: string(pwd),
		Id:       id,
	}
	dbStructure.Users[id] = u
	db.writeDB(dbStructure)
	return user{Id: id, Email: email}, nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	DBBytes, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}
	dbStructure := DBStructure{}
	err = json.Unmarshal(DBBytes, &dbStructure)
	if err != nil {
		return DBStructure{}, err
	}
	return dbStructure, nil
}

// writeDB saves the database to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	dat, err := json.MarshalIndent(dbStructure, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, dat, 0644)
}

// createChirp creates a chirp and saves it to the database
func (db *DB) createChirp(body string) (chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	err := db.ensureDB()
	if err != nil {
		return chirp{}, err
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		return chirp{}, err
	}
	id := 0
	for k := range dbStructure.Chirps {
		if k > id {
			id = k
		}
	}
	id++
	c := chirp{
		Body: body,
		Id:   id,
	}
	dbStructure.Chirps[id] = c
	db.writeDB(dbStructure)
	return c, nil
}

// getChirpByID returns a chirp by chirpID
func (db *DB) getChirpByID(chirpID int) (chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	err := db.ensureDB()
	if err != nil {
		return chirp{}, err
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		return chirp{}, err
	}
	ch := dbStructure.Chirps[chirpID]
	if ch.Body == "" {
		return chirp{}, fmt.Errorf("chirp not found")
	}
	return ch, nil
}

// getChirps returns all chirps in the database
func (db *DB) getChirps() ([]chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	err := db.ensureDB()
	if err != nil {
		return nil, err
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	var chirps []chirp
	for _, c := range dbStructure.Chirps {
		chirps = append(chirps, c)
	}
	return chirps, nil
}

// ensureDB checks if the database file exists, if not, it creates it
func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if err != nil {
		dbStructure := DBStructure{}
		dat, err := json.Marshal(dbStructure)
		if err != nil {
			return err
		}
		os.WriteFile(db.path, dat, 0644)
	}
	return nil
}

// apiConfig is a struct that contains the number of hits to the file server
type apiConfig struct {
	jwtSecret      string
	fileServerHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html;")
	w.WriteHeader(http.StatusOK)
	s := fmt.Sprintf(`
		<html>
		
		<body>
		    <h1>Welcome, Chirpy Admin</h1>
		    <p>Chirpy has been visited %d times!</p>
		</body>
		
		</html>
	`, cfg.fileServerHits)
	w.Write([]byte(s))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	cfg.fileServerHits = 0
}

var db *DB

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	apiCfg := apiConfig{}
	apiCfg.jwtSecret = jwtSecret

	db = &DB{
		path: "prodDB",
		mux:  &sync.RWMutex{},
	}
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		fmt.Print("debuging...")
		db, _ = newDB("database.json")
	}
	appRouter := chi.NewRouter()
	apiRouter := chi.NewRouter()
	metricsRouter := chi.NewRouter()
	handler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	appRouter.Handle("/app/*", apiCfg.middlewareMetricsInc(handler))
	appRouter.Handle("/app", apiCfg.middlewareMetricsInc(handler))
	apiRouter.Post("/chirps", http.HandlerFunc(validateChirp))
	apiRouter.Get("/chirps", http.HandlerFunc(getChirps))
	apiRouter.Get("/chirps/{chirpID}", http.HandlerFunc(getChirpByID))
	apiRouter.Post("/users", http.HandlerFunc(createUser))
	apiRouter.Put("/users", http.HandlerFunc(apiCfg.updateUserHandle))
	apiRouter.Post("/login", http.HandlerFunc(apiCfg.attemptLogin))
	apiRouter.Get("/healthz", http.HandlerFunc(ready))
	metricsRouter.Get("/metrics", http.HandlerFunc(apiCfg.getHits))
	apiRouter.Handle("/reset", http.HandlerFunc(apiCfg.reset))
	appRouter.Mount("/api", apiRouter)
	appRouter.Mount("/admin", metricsRouter)

	corsMux := middlewareCors(appRouter)
	// Create a new http.Server and use the corsMux as the handler
	serve := http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}
	serve.ListenAndServe()
}

func (cfg *apiConfig) updateUserHandle(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	// strip prefix "Bearer " from Token
	authToken := strings.TrimPrefix(header, "Bearer ")
	token, err := jwt.ParseWithClaims(authToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusUnauthorized, "bad token")
		return
	}
	stringId, err := token.Claims.GetSubject()
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusUnauthorized, "bad token")
		return
	}
	id, err := strconv.Atoi(stringId)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusUnauthorized, "bad token")
		return
	}
	// get the body
	decoder := json.NewDecoder(r.Body)
	sentUser := user{}
	err = decoder.Decode(&sentUser)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "bad user format")
		return
	}
	user, err := db.updateUser(id, sentUser)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusUnauthorized, "bad token")
		return
	}
	respondWithJSON(w, http.StatusOK, user)
}

func (cfg *apiConfig) attemptLogin(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	sentUser := user{}
	err := decoder.Decode(&sentUser)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "bad user format")
		return
	}
	dbUser, err := db.lookupUserByEmail(sentUser.Email)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "user not found")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(sentUser.Password))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "bad password")
		return
	}

	if dbUser.ExpiresIn == 0 || dbUser.ExpiresIn > 24*60*60 {
		dbUser.ExpiresIn = 24 * 60 * 60
	}

	claim := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(dbUser.ExpiresIn))),
		Subject:   strconv.Itoa(dbUser.Id),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claim)
	signedJWT, err := token.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "server error")
		return
	}
	respondWithJSON(w, http.StatusOK, user{Email: dbUser.Email, Token: signedJWT, Id: dbUser.Id})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	u := user{}
	err := decoder.Decode(&u)
	if err != nil {
		// return json error
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "something went wrong")
		return
	}
	// return json success with id
	user, err := db.createUser(u.Email, u.Password)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, user)
}

func getChirpByID(w http.ResponseWriter, r *http.Request) {
	// get the chirpID
	chirpID := r.PathValue("chirpID")
	ID, err := strconv.Atoi(chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		// w.WriteHeader(http.StatusNotFound)
		return
	}
	chirp, err := db.getChirpByID(ID)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, chirp)
}

func getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := db.getChirps()
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sortChirps(chirps)
	respondWithJSON(w, http.StatusOK, chirps)
}

// sortChirps sorts the chirps by id
func sortChirps(chirps []chirp) {
	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].Id < chirps[j].Id
	})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	dat, _ := json.Marshal(map[string]string{"error": message})
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	ch := chirp{}
	err := decoder.Decode(&ch)
	if err != nil {
		// return json error
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "something went wrong")
		return
	}
	// check if the chirp body is empty
	if ch.Body == "" {
		// return json error
		respondWithError(w, http.StatusBadRequest, "chirp body is empty")
		return
	}
	// check the lenght of the chirp body
	if len(ch.Body) >= 140 {
		// return json error
		respondWithError(w, http.StatusBadRequest, "chirp body is too long")
		return
	}
	// return json success with id
	cleanChirp, err := db.createChirp(cleaningChirp(ch.Body))
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusBadRequest, "something went wrong")
		return
	}
	respondWithJSON(w, http.StatusCreated, cleanChirp)
}

// clean chirps from the words: {kerfuffle,sharbert,fornax}
func cleaningChirp(old string) (new string) {
	new = strings.ReplaceAll(old, "kerfuffle", "****")
	new = strings.ReplaceAll(new, "Kerfuffle", "****")
	new = strings.ReplaceAll(new, "sharbert", "****")
	new = strings.ReplaceAll(new, "Sharbert", "****")
	new = strings.ReplaceAll(new, "fornax", "****")
	new = strings.ReplaceAll(new, "Fornax", "****")
	return new
}

func ready(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, "OK")
	// // change Content-Type: text/plain; charset=utf-8
	// w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// // change status code to 200
	// w.WriteHeader(http.StatusOK)
	// // change response body
	// w.Write([]byte("OK"))
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
