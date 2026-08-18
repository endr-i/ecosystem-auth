package ratelimit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Policy maps a route/method identifier to its limit. Identifiers without an
// entry are not limited.
type Policy map[string]Limit

// DefaultPolicy returns sensible per-IP limits for auth endpoints.
func DefaultPolicy() Policy {
	return Policy{
		"register": {Requests: 5, Window: time.Minute},
		"login":    {Requests: 10, Window: time.Minute},
		// "refresh" covers HTTP, "refreshtoken" the gRPC method name.
		"refresh":      {Requests: 30, Window: time.Minute},
		"refreshtoken": {Requests: 30, Window: time.Minute},
		"logout":       {Requests: 30, Window: time.Minute},
	}
}

// Middleware wraps an HTTP handler with a per-IP rate limit. On Redis
// failure it fails open and logs the error.
func (l *Limiter) Middleware(name string, limit Limit, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		res, err := l.Allow(r.Context(), name+":"+ip, limit)
		if err != nil {
			log.Error("rate limiter unavailable, failing open", "err", err)
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
		if !res.Allowed {
			seconds := int(res.RetryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UnaryInterceptor rate-limits gRPC methods per client IP using the given
// policy, keyed by the method's lowercased short name (e.g. "login" for
// /auth.v1.AuthService/Login). On Redis failure it fails open.
func (l *Limiter) UnaryInterceptor(policy Policy, log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		name := shortMethodName(info.FullMethod)
		limit, ok := policy[name]
		if !ok {
			return handler(ctx, req)
		}
		res, err := l.Allow(ctx, name+":"+peerIP(ctx), limit)
		if err != nil {
			log.Error("rate limiter unavailable, failing open", "err", err)
			return handler(ctx, req)
		}
		if !res.Allowed {
			return nil, status.Errorf(codes.ResourceExhausted,
				"rate limit exceeded, retry in %ds", int(res.RetryAfter.Seconds())+1)
		}
		return handler(ctx, req)
	}
}

func shortMethodName(fullMethod string) string {
	if i := strings.LastIndexByte(fullMethod, '/'); i >= 0 {
		fullMethod = fullMethod[i+1:]
	}
	return strings.ToLower(fullMethod)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
