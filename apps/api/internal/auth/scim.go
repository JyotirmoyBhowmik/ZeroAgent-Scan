package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SCIMService handles SCIM 2.0 (RFC 7643 / RFC 7644) automated user lifecycle events.
type SCIMService struct {
	repo AuthRepository
}

// NewSCIMService creates an initialized SCIM 2.0 service.
func NewSCIMService(repo AuthRepository) *SCIMService {
	return &SCIMService{repo: repo}
}

// ProvisionUser creates a new user from a SCIM payload.
func (s *SCIMService) ProvisionUser(tenantID string, scimUser SCIMUser) (*SCIMUser, error) {
	if scimUser.UserName == "" {
		return nil, fmt.Errorf("scim: userName is required")
	}

	email := scimUser.UserName
	if len(scimUser.Emails) > 0 {
		email = scimUser.Emails[0].Value
	}

	role := RoleViewer
	if len(scimUser.Roles) > 0 {
		role = Role(strings.ToLower(scimUser.Roles[0].Value))
	}

	id := scimUser.ID
	if id == "" {
		id = uuid.New().String()
	}

	user := User{
		ID:           id,
		TenantID:     tenantID,
		Username:     scimUser.UserName,
		Email:        email,
		DisplayName:  scimUser.Name.Formatted,
		Role:         role,
		IsActive:     scimUser.Active,
		IsBreakGlass: false,
		TOTPEnabled:  false,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.repo.SaveUser(user); err != nil {
		return nil, err
	}

	return s.toSCIMUser(user), nil
}

// DeprovisionUser sets active=false or removes a user based on SCIM requests.
func (s *SCIMService) DeprovisionUser(tenantID, userID string) error {
	user, exists := s.repo.GetUserByID(userID)
	if !exists || user.TenantID != tenantID {
		return fmt.Errorf("scim: user %s not found", userID)
	}

	user.IsActive = false
	user.UpdatedAt = time.Now().UTC()
	return s.repo.SaveUser(*user)
}

// GetSCIMUser retrieves a user formatted as a SCIM 2.0 resource.
func (s *SCIMService) GetSCIMUser(tenantID, userID string) (*SCIMUser, error) {
	user, exists := s.repo.GetUserByID(userID)
	if !exists || user.TenantID != tenantID {
		return nil, fmt.Errorf("scim: user not found")
	}
	return s.toSCIMUser(*user), nil
}

// ListSCIMUsers returns a paginated SCIM 2.0 list response.
func (s *SCIMService) ListSCIMUsers(tenantID string) (*SCIMListResponse, error) {
	users := s.repo.ListUsers(tenantID)
	var scimUsers []SCIMUser
	for _, u := range users {
		scimUsers = append(scimUsers, *s.toSCIMUser(u))
	}

	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(scimUsers),
		StartIndex:   1,
		ItemsPerPage: len(scimUsers),
		Resources:    scimUsers,
	}, nil
}

func (s *SCIMService) toSCIMUser(u User) *SCIMUser {
	return &SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       u.ID,
		UserName: u.Username,
		Name: SCIMName{
			Formatted: u.DisplayName,
		},
		Emails: []SCIMEmail{
			{Value: u.Email, Type: "work", Primary: true},
		},
		Roles: []SCIMRole{
			{Value: string(u.Role), Primary: true},
		},
		Active: u.IsActive,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     "/api/v1/scim/v2/Users/" + u.ID,
		},
	}
}
