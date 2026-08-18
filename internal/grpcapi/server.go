// Package grpcapi exposes the auth service over gRPC.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/endr-i/ecosystem-auth/gen/auth/v1"
	"github.com/endr-i/ecosystem-auth/internal/auth"
	"github.com/endr-i/ecosystem-auth/internal/user"
)

type Server struct {
	authv1.UnimplementedAuthServiceServer

	auth  *auth.Service
	users *user.Repository
	log   *slog.Logger
}

func NewServer(a *auth.Service, u *user.Repository, log *slog.Logger) *Server {
	return &Server{auth: a, users: u, log: log}
}

func toProtoUser(u *user.User) *authv1.User {
	return &authv1.User{
		Id:            u.ID,
		Email:         u.Email,
		Phone:         u.Phone,
		PhoneVerified: u.PhoneVerified,
		MfaEnabled:    u.MFAEnabled,
		CreatedAt:     timestamppb.New(u.CreatedAt),
	}
}

func toProtoTokens(p *auth.TokenPair) *authv1.TokenPair {
	return &authv1.TokenPair{
		AccessToken:  p.AccessToken,
		RefreshToken: p.RefreshToken,
		TokenType:    p.TokenType,
		ExpiresIn:    p.ExpiresIn,
	}
}

func (s *Server) mapError(err error) error {
	switch {
	case errors.Is(err, auth.ErrValidation):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, user.ErrEmailTaken):
		return status.Error(codes.AlreadyExists, "email already registered")
	case errors.Is(err, auth.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "invalid email or password")
	case errors.Is(err, auth.ErrInvalidToken):
		return status.Error(codes.Unauthenticated, "invalid or expired token")
	case errors.Is(err, user.ErrNotFound):
		return status.Error(codes.NotFound, "user not found")
	default:
		s.log.Error("grpc internal error", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
}

func (s *Server) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	u, err := s.auth.Register(ctx, req.GetEmail(), req.GetPassword(), req.GetPhone())
	if err != nil {
		return nil, s.mapError(err)
	}
	return &authv1.RegisterResponse{User: toProtoUser(u)}, nil
}

func (s *Server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	u, pair, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, s.mapError(err)
	}
	return &authv1.LoginResponse{User: toProtoUser(u), Tokens: toProtoTokens(pair)}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	pair, err := s.auth.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, s.mapError(err)
	}
	return &authv1.RefreshTokenResponse{Tokens: toProtoTokens(pair)}, nil
}

func (s *Server) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	if err := s.auth.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, s.mapError(err)
	}
	return &authv1.LogoutResponse{}, nil
}

func (s *Server) ValidateToken(_ context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	userID, err := s.auth.VerifyAccessToken(req.GetAccessToken())
	if err != nil {
		return &authv1.ValidateTokenResponse{Valid: false}, nil
	}
	return &authv1.ValidateTokenResponse{Valid: true, UserId: userID}, nil
}

func (s *Server) GetMe(ctx context.Context, req *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	userID, err := s.auth.VerifyAccessToken(req.GetAccessToken())
	if err != nil {
		return nil, s.mapError(err)
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, s.mapError(err)
	}
	return &authv1.GetMeResponse{User: toProtoUser(u)}, nil
}
