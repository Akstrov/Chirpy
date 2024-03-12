package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

type chirp struct {
	Body string `json:"body"`
	Id   int    `json:"id"`
}

type DB struct {
	mux  *sync.RWMutex
	path string
}
type DBStructure struct {
	Chirps map[int]chirp `json:"chirps"`
}

func newDB(path string) (*DB, error) {
	dbStructure := DBStructure{Chirps: make(map[int]chirp)}
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

// TODO: complete loadDB
// func (db *DB) loadDB

func (db *DB) createChirp(body string) (chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	err := db.ensureDB()
	if err != nil {
		return chirp{}, err
	}
	chirpsBytes, err := os.ReadFile(db.path)
	if err != nil {
		return chirp{}, err
	}
	// chirpsBytes to the map
	dbStructure := DBStructure{}
	err = json.Unmarshal(chirpsBytes, &dbStructure)
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
	dat, _ := json.MarshalIndent(dbStructure, "", " ")
	err = os.WriteFile(db.path, dat, 0644)
	if err != nil {
		return chirp{}, err
	}

	return c, nil
}

func (db *DB) getChirps() ([]chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	err := db.ensureDB()
	if err != nil {
		return nil, err
	}
	chirpsBytes, err := os.ReadFile(db.path)
	if err != nil {
		return nil, err
	}
	dbStructure := DBStructure{}
	err = json.Unmarshal(chirpsBytes, &dbStructure)
	if err != nil {
		return nil, err
	}
	var chirps []chirp
	for _, c := range dbStructure.Chirps {
		chirps = append(chirps, c)
	}
	return chirps, nil
}

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

type apiConfig struct {
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
	db, _ = newDB("database.json")
	appRouter := chi.NewRouter()
	apiRouter := chi.NewRouter()
	metricsRouter := chi.NewRouter()
	apiCfg := apiConfig{}
	handler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	appRouter.Handle("/app/*", apiCfg.middlewareMetricsInc(handler))
	appRouter.Handle("/app", apiCfg.middlewareMetricsInc(handler))
	// apiRouter.Post("/validate_chirp", http.HandlerFunc(validateChirp))
	apiRouter.Post("/chirps", http.HandlerFunc(validateChirp))
	apiRouter.Get("/chirps", http.HandlerFunc(getChirps))
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

func getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := db.getChirps()
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sortChirps(chirps)
	dat, _ := json.Marshal(chirps)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

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
	// change Content-Type: text/plain; charset=utf-8
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// change status code to 200
	w.WriteHeader(http.StatusOK)
	// change response body
	w.Write([]byte("OK"))
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
