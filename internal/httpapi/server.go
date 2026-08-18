package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/endr-i/ecosystem-auth/internal/auth"
	"github.com/endr-i/ecosystem-auth/internal/user"
)

type Server struct {
	auth  *auth.Service
	users *user.Repository
	log   *slog.Logger
}

func NewServer(a *auth.Service, u *user.Repository, log *slog.Logger) *Server {
	return &Server{auth: a, users: u, log: log}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/refresh", s.handleRefresh)
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	mux.Handle("GET /api/v1/me", s.requireAuth(http.HandlerFunc(s.handleMe)))
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.withLogging(mux)
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !s.decode(w, r, &req) {
		return
	}
	u, err := s.auth.Register(r.Context(), req.Email, req.Password, req.Phone)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrValidation):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, user.ErrEmailTaken):
			s.writeError(w, http.StatusConflict, "email already registered")
		default:
			s.internalError(w, r, err)
		}
		return
	}
	s.writeJSON(w, http.StatusCreated, u)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !s.decode(w, r, &req) {
		return
	}
	u, pair, err := s.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"user": u, "tokens": pair})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !s.decode(w, r, &req) {
		return
	}
	pair, err := s.auth.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			s.writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, pair)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !s.decode(w, r, &req) {
		return
	}
	if err := s.auth.Logout(r.Context(), req.RefreshToken); err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(ctxUserID{}).(string)
	u, err := s.users.GetByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "user no longer exists")
			return
		}
		s.internalError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type ctxUserID struct{}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		tokenStr, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || tokenStr == "" {
			s.writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		userID, err := s.auth.VerifyAccessToken(tokenStr)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID{}, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	})
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "path", r.URL.Path, "err", err)
	s.writeError(w, http.StatusInternalServerError, "internal server error")
}
