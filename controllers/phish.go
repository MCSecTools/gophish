package controllers

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/gophish/gophish/config"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/controllers/api"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/util"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jordan-wright/unindexed"
)

// ErrInvalidRequest is thrown when a request with an invalid structure is
// received
var ErrInvalidRequest = errors.New("Invalid request")

// ErrCampaignComplete is thrown when an event is received for a campaign that
// has already been marked as complete.
var ErrCampaignComplete = errors.New("Event received on completed campaign")

// TransparencyResponse is the JSON response provided when a third-party
// makes a request to the transparency handler.
type TransparencyResponse struct {
	Server         string    `json:"server"`
	ContactAddress string    `json:"contact_address"`
	SendDate       time.Time `json:"send_date"`
}

// TransparencySuffix (when appended to a valid result ID), will cause Gophish
// to return a transparency response.
const TransparencySuffix = "+"

// PhishingServerOption is a functional option that is used to configure the
// the phishing server
type PhishingServerOption func(*PhishingServer)

// PhishingServer is an HTTP server that implements the campaign event
// handlers, such as email open tracking, click tracking, and more.
type PhishingServer struct {
	server         *http.Server
	config         config.PhishServer
	contactAddress string
}

// NewPhishingServer returns a new instance of the phishing server with
// provided options applied.
func NewPhishingServer(config config.PhishServer, options ...PhishingServerOption) *PhishingServer {
	defaultServer := &http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         config.ListenURL,
	}
	ps := &PhishingServer{
		server: defaultServer,
		config: config,
	}
	for _, opt := range options {
		opt(ps)
	}
	ps.registerRoutes()
	return ps
}

// WithContactAddress sets the contact address used by the transparency
// handlers
func WithContactAddress(addr string) PhishingServerOption {
	return func(ps *PhishingServer) {
		ps.contactAddress = addr
	}
}

// Verifica el token de Turnstile con Cloudflare
func VerifyTurnstileToken(token, remoteIP string) (bool, error) {
	secretKey := "tu_clave_secreta"
	endpoint := "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	resp, err := http.PostForm(endpoint, url.Values{
		"secret":   {secretKey},
		"response": {token},
		"remoteip": {remoteIP},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"` // Opcional, maneja según tu necesidad
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, err
	}

	return result.Success, nil
}

// Overwrite net.https Error with a custom one to set our own headers
// Go's internal Error func returns text/plain so browser's won't render the html
func customError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Server", "nginx/1.29")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "default-src *  data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval' 'unsafe-dynamic'; script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src * data: blob: 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src * data: blob: ; style-src * data: blob: 'unsafe-inline'; font-src * data: blob: 'unsafe-inline'; frame-ancestors * data: blob: 'unsafe-inline';")
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

// Overwrite go's internal not found to allow templating the not found page
// The templating string is currently not passed in, therefore there is no templating yet
// If I need it in the future, it's a 5 minute change...
func customNotFound(w http.ResponseWriter, r *http.Request) {
	tmpl404, err := template.ParseFiles("templates/404.html")
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	err = tmpl404.Execute(&b, "")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	customError(w, b.String(), http.StatusNotFound)
}

// Start launches the phishing server, listening on the configured address.
func (ps *PhishingServer) Start() {
	if ps.config.UseTLS {
		// Only support TLS 1.2 and above - ref #1691, #1689
		ps.server.TLSConfig = defaultTLSConfig
		err := util.CheckAndCreateSSL(ps.config.CertPath, ps.config.KeyPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Starting phishing server at https://%s", ps.config.ListenURL)
		log.Fatal(ps.server.ListenAndServeTLS(ps.config.CertPath, ps.config.KeyPath))
	}
	// If TLS isn't configured, just listen on HTTP
	log.Infof("Starting phishing server at http://%s", ps.config.ListenURL)
	log.Fatal(ps.server.ListenAndServe())
}

// Shutdown attempts to gracefully shutdown the server.
func (ps *PhishingServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return ps.server.Shutdown(ctx)
}

// TurnstileMiddleware verifica el token de Turnstile en las solicitudes antes de permitir el acceso a rutas protegidas.
func (ps *PhishingServer) TurnstileMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extraer el token de Turnstile de los headers o del query string
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		} else {
			token = r.URL.Query().Get("turnstile_token")
		}

		if token == "" {
			log.Error("No Turnstile token provided")
			http.Error(w, "Access denied: No Turnstile token provided", http.StatusUnauthorized)
			return
		}

		// Verificar el token de Turnstile
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Errorf("Error extracting IP address: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		isValid, err := VerifyTurnstileToken(token, remoteIP)
		if err != nil {
			log.Errorf("Failed to verify Turnstile token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !isValid {
			log.Errorf("Invalid Turnstile token")
			http.Error(w, "Access denied: Invalid Turnstile token", http.StatusUnauthorized)
			return
		}

		// Si el token es válido, continúa con el manejo de la solicitud
		next.ServeHTTP(w, r)
	})
}

func (ps *PhishingServer) registerRoutes() {
	router := mux.NewRouter()
	fileServer := http.FileServer(unindexed.Dir("./static/endpoint/"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))

	// Ruta específica para verificar
	router.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/verify.html")
	})

	// Setup GZIP compression y otras configuraciones de middleware
	gzipWrapper, _ := gziphandler.NewGzipLevelHandler(gzip.BestCompression)
	phishHandler := gzipWrapper(router)
	phishHandler = handlers.ProxyHeaders(phishHandler)
	phishHandler = handlers.CombinedLoggingHandler(log.Writer(), phishHandler)

	// Aplicar middleware que verifica y posiblemente redirige si el token es inválido
	verifyAndRedirectHandler := ps.VerifyHandler(phishHandler)

	// Configurar las rutas que estarán protegidas
	router.Handle("/track", verifyAndRedirectHandler)
	router.Handle("/{path:.*}/track", verifyAndRedirectHandler)
	router.Handle("/{path:.*}/report", verifyAndRedirectHandler)
	router.Handle("/report", verifyAndRedirectHandler)
	router.Handle("/{path:.*}", verifyAndRedirectHandler) // Protege esta ruta general con el middleware

	ps.server.Handler = phishHandler
}

// VerifyHandler verifica la respuesta de Turnstile. Si no está validada, redirige a /verify.
func (ps *PhishingServer) VerifyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extraer el token de Turnstile de los headers o del query string
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		} else {
			token = r.URL.Query().Get("turnstile_token")
		}

		// Verificar el token de Turnstile
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Errorf("Error extracting IP address: %v", err)
			http.NotFound(w, r)
			return
		}
		if token == "" {
			log.Errorf("No Turnstile token provided, redirecting to /verify")
			http.Redirect(w, r, "/verify", http.StatusFound)
			return
		}
		isValid, err := VerifyTurnstileToken(token, remoteIP)
		if err != nil {
			log.Errorf("Failed to verify Turnstile token: %v", err)
			http.NotFound(w, r)
			return
		}
		if !isValid {
			log.Errorf("Invalid Turnstile token, redirecting to /verify")
			http.Redirect(w, r, "/verify", http.StatusFound)
			return
		}
		// Si el token es válido, continúa con el manejo de la solicitud
		next.ServeHTTP(w, r)
	})
}

// TrackHandler tracks emails as they are opened, updating the status for the given Result
func (ps *PhishingServer) TrackHandler(w http.ResponseWriter, r *http.Request) {
	r, err := setupContext(r)
	if err != nil {
		// Log the error if it wasn't something we can safely ignore
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		customNotFound(w, r)
		return
	}
	// Check for a preview
	if _, ok := ctx.Get(r, "result").(models.EmailRequest); ok {
		http.ServeFile(w, r, "static/images/witness.png")
		return
	}
	rs := ctx.Get(r, "result").(models.Result)
	Post_Id := ctx.Get(r, "post_id").(string)
	d := ctx.Get(r, "details").(models.EventDetails)

	// Check for a transparency request
	if strings.HasSuffix(Post_Id, TransparencySuffix) {
		ps.TransparencyHandler(w, r)
		return
	}

	err = rs.HandleEmailOpened(d)
	if err != nil {
		log.Error(err)
	}
	http.ServeFile(w, r, "static/images/witness.png")
}

// ReportHandler tracks emails as they are reported, updating the status for the given Result
func (ps *PhishingServer) ReportHandler(w http.ResponseWriter, r *http.Request) {
	r, err := setupContext(r)
	w.Header().Set("Access-Control-Allow-Origin", "*") // To allow Chrome extensions (or other pages) to report a campaign without violating CORS
	if err != nil {
		// Log the error if it wasn't something we can safely ignore
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		customNotFound(w, r)
		return
	}
	// Check for a preview
	if _, ok := ctx.Get(r, "result").(models.EmailRequest); ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rs := ctx.Get(r, "result").(models.Result)
	Post_Id := ctx.Get(r, "post_id").(string)
	d := ctx.Get(r, "details").(models.EventDetails)

	// Check for a transparency request
	if strings.HasSuffix(Post_Id, TransparencySuffix) {
		ps.TransparencyHandler(w, r)
		return
	}

	err = rs.HandleEmailReport(d)
	if err != nil {
		log.Error(err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// PhishHandler handles incoming client connections and manages the actions performed,
// such as checking clicked links or form submissions, after verifying a Turnstile token.
func (ps *PhishingServer) PhishHandler(w http.ResponseWriter, r *http.Request) {
	// Setup the context for the request
	r, err := setupContext(r)
	if err != nil {
		// Log any significant errors that aren't just invalid requests or completed campaigns
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		customNotFound(w, r)
		return
	}

	// Extract Turnstile token from the request
	token := r.FormValue("turnstile_token")
	if token == "" {
		log.Error("No Turnstile token provided")
		customError(w, "Access denied: No Turnstile token provided", http.StatusUnauthorized)
		return
	}

	// Verify Turnstile token
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	isValid, err := VerifyTurnstileToken(token, remoteIP)
	if err != nil {
		log.Error("Turnstile verification failed: ", err)
		customError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isValid {
		log.Error("Invalid Turnstile token")
		customError(w, "Access denied: Invalid Turnstile token", http.StatusUnauthorized)
		return
	}

	// Proceed with handling the request after successful Turnstile verification
	processRequest(ps, w, r)
}

// processRequest processes the phishing related requests after Turnstile verification.
func processRequest(ps *PhishingServer, w http.ResponseWriter, r *http.Request) {
	rs := ctx.Get(r, "result").(models.Result)
	Post_Id := ctx.Get(r, "post_id").(string)
	c := ctx.Get(r, "campaign").(models.Campaign)
	d := ctx.Get(r, "details").(models.EventDetails)

	// Handle transparency requests
	if strings.HasSuffix(Post_Id, TransparencySuffix) {
		ps.TransparencyHandler(w, r)
		return
	}

	p, err := models.GetPage(c.PageId, c.UserId)
	if err != nil {
		log.Error(err)
		customNotFound(w, r)
		return
	}

	// Process the request based on the method
	switch r.Method {
	case "GET":
		err = rs.HandleClickedLink(d)
	case "POST":
		err = rs.HandleFormSubmit(d)
	}

	if err != nil {
		log.Error(err)
		customNotFound(w, r)
		return
	}

	ptx, err := models.NewPhishingTemplateContext(&c, rs.BaseRecipient, rs.POSTId)
	if err != nil {
		log.Error(err)
		customNotFound(w, r)
		return
	}

	renderPhishResponse(w, r, ptx, p)
}

// renderPhishResponse handles rendering the correct response to the phishing
// connection. This usually involves writing out the page HTML or redirecting
// the user to the correct URL.
func renderPhishResponse(w http.ResponseWriter, r *http.Request, ptx models.PhishingTemplateContext, p models.Page) {
	// If the request was a form submit and a redirect URL was specified, we
	// should send the user to that URL
	if r.Method == "POST" {
		if p.RedirectURL != "" {
			redirectURL, err := models.ExecuteTemplate(p.RedirectURL, ptx)
			if err != nil {
				log.Error(err)
				customNotFound(w, r)
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}
	// Otherwise, we just need to write out the templated HTML
	html, err := models.ExecuteTemplate(p.HTML, ptx)
	if err != nil {
		log.Error(err)
		customNotFound(w, r)
		return
	}
	w.Write([]byte(html))
}

// RobotsHandler prevents search engines, etc. from indexing phishing materials
func (ps *PhishingServer) RobotsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "User-agent: Googlebot\nDisallow: /\nDisallow: /*?")
	fmt.Fprintln(w, "User-agent: *\nDisallow: /\nDisallow: /*?\nCrawl-delay: 9")
}

// TransparencyHandler returns a TransparencyResponse for the provided result
// and campaign.
func (ps *PhishingServer) TransparencyHandler(w http.ResponseWriter, r *http.Request) {
	rs := ctx.Get(r, "result").(models.Result)
	tr := &TransparencyResponse{
		Server:         config.ServerName,
		SendDate:       rs.SendDate,
		ContactAddress: ps.contactAddress,
	}
	api.JSONResponse(w, tr, http.StatusOK)
}

// setupContext handles some of the administrative work around receiving a new
// request, such as checking the result ID, the campaign, etc.
func setupContext(r *http.Request) (*http.Request, error) {
	err := r.ParseForm()
	if err != nil {
		log.Error(err)
		return r, err
	}
	Post_Id := r.Form.Get(models.RecipientParameter)
	if Post_Id == "" {
		return r, ErrInvalidRequest
	}
	// Since we want to support the common case of adding a "+" to indicate a
	// transparency request, we need to take care to handle the case where the
	// request ends with a space, since a "+" is technically reserved for use
	// as a URL encoding of a space.
	if strings.HasSuffix(Post_Id, " ") {
		// We'll trim off the space
		Post_Id = strings.TrimRight(Post_Id, " ")
		// Then we'll add the transparency suffix
		Post_Id = fmt.Sprintf("%s%s", Post_Id, TransparencySuffix)
	}
	// Finally, if this is a transparency request, we'll need to verify that
	// a valid Post_Id has been provided, so we'll look up the result with a
	// trimmed parameter.
	id := strings.TrimSuffix(Post_Id, TransparencySuffix)
	// Check to see if this is a preview or a real result
	if strings.HasPrefix(id, models.PreviewPrefix) {
		rs, err := models.GetEmailRequestByResultId(id)
		if err != nil {
			return r, err
		}
		r = ctx.Set(r, "result", rs)
		return r, nil
	}
	rs, err := models.GetResult(id)
	if err != nil {
		return r, err
	}
	c, err := models.GetCampaign(rs.CampaignId, rs.UserId)
	if err != nil {
		log.Error(err)
		return r, err
	}
	// Don't process events for completed campaigns
	if c.Status == models.CampaignComplete {
		return r, ErrCampaignComplete
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	// Handle post processing such as GeoIP
	err = rs.UpdateGeo(ip)
	if err != nil {
		log.Error(err)
	}
	d := models.EventDetails{
		Payload: r.Form,
		Browser: make(map[string]string),
	}
	d.Browser["address"] = ip
	d.Browser["user-agent"] = r.Header.Get("User-Agent")

	r = ctx.Set(r, "post_id", Post_Id)
	r = ctx.Set(r, "result", rs)
	r = ctx.Set(r, "campaign", c)
	r = ctx.Set(r, "details", d)
	return r, nil
}
