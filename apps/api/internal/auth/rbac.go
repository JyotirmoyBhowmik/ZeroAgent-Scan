package auth

var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {
		PermissionReadTelemetry:   true,
		PermissionReadCompliance:  true,
		PermissionReadFindings:    true,
		PermissionReadDrift:       true,
		PermissionGenerateReports: true,
	},
	RoleOperator: {
		PermissionReadTelemetry:    true,
		PermissionReadCompliance:   true,
		PermissionReadFindings:     true,
		PermissionReadDrift:        true,
		PermissionTriggerScans:     true,
		PermissionCancelScans:      true,
		PermissionAcknowledgeDrift: true,
		PermissionGenerateReports:  true,
	},
	RoleAuditor: {
		PermissionReadTelemetry:   true,
		PermissionReadCompliance:  true,
		PermissionReadFindings:    true,
		PermissionReadDrift:       true,
		PermissionReadAuditLogs:   true,
		PermissionGenerateReports: true,
	},
	RoleAdmin: {
		PermissionReadTelemetry:     true,
		PermissionReadCompliance:    true,
		PermissionReadFindings:      true,
		PermissionReadDrift:         true,
		PermissionReadAuditLogs:     true,
		PermissionTriggerScans:      true,
		PermissionCancelScans:       true,
		PermissionAcknowledgeDrift:  true,
		PermissionManageAlerts:      true,
		PermissionManageCredentials: true,
		PermissionManageUsers:       true,
		PermissionGenerateReports:   true,
	},
	RoleSuperAdmin: {
		PermissionReadTelemetry:     true,
		PermissionReadCompliance:    true,
		PermissionReadFindings:      true,
		PermissionReadDrift:         true,
		PermissionReadAuditLogs:     true,
		PermissionTriggerScans:      true,
		PermissionCancelScans:       true,
		PermissionAcknowledgeDrift:  true,
		PermissionManageAlerts:      true,
		PermissionManageCredentials: true,
		PermissionManageUsers:       true,
		PermissionManageTenants:     true,
		PermissionGenerateReports:   true,
	},
}

// GetRolePermissions returns all permissions granted to a role.
func GetRolePermissions(role Role) []Permission {
	permsMap, exists := rolePermissions[role]
	if !exists {
		return nil
	}
	var perms []Permission
	for p := range permsMap {
		perms = append(perms, p)
	}
	return perms
}

// HasPermission checks whether a given role has a specific permission.
func HasPermission(role Role, perm Permission) bool {
	permsMap, exists := rolePermissions[role]
	if !exists {
		return false
	}
	return permsMap[perm]
}

// HasAllPermissions checks whether a given role satisfies all requested permissions.
func HasAllPermissions(role Role, perms ...Permission) bool {
	for _, p := range perms {
		if !HasPermission(role, p) {
			return false
		}
	}
	return true
}
