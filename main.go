package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import "golang.org/x/crypto/bcrypt"

import "net/http"

// Allows you to pass values between functions
// Such as an error message
// https://golang.org/pkg/context/
import "context"

// Use templates to add custom values
// Such as an error message
// https://golang.org/pkg/html/template/
import "html/template"

// Caches all the templates from the views folder int the value views
// The full path to the views folder
var views = template.Must(template.ParseGlob("/home/yourusername/work/src/github.com/yourusername/go-login/views/*.html"))

// Used by context
type key int

const MyKey key = 0

// Error messages will be type struct for context to pass around
type loginerror struct {
	// And the message is stored as a string
	// Skip down to the next comment
	Err string
}

var db *sql.DB
var err error

func signupPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "signup.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var user string

	err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		res.Write([]byte("User created!"))
		return
	case err != nil:
		http.Error(res, "Server error, unable to create your account.", 500)
		return
	default:
		http.Redirect(res, req, "/", 301)
	}
}

// This function gets called if a login error occurs
func login(res http.ResponseWriter, req *http.Request) {
	// grab the context value (the message)
	// le short for login error
	le, _ := req.Context().Value(MyKey).(loginerror)
	// send the user the login template with the error message
	views.ExecuteTemplate(res, "Login", loginerror{le.Err})
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "login.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	err := db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&databaseUsername, &databasePassword)

	// uh oh error! let's tell the user
	if err != nil {
		// Create the error message
		le := loginerror{"No user with that username!"}
		// Put it in a context
		ctx := context.WithValue(req.Context(), MyKey, le)
		// Pass it to the login function
		login(res, req.WithContext(ctx))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	res.Write([]byte("Hello" + databaseUsername))

}

func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "index.html")
}

func main() {
	db, err = sql.Open("mysql", "root:<password>@/<dbname>")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/", homePage)
	http.ListenAndServe(":8080", nil)
}
