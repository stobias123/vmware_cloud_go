package vmware_cloud_go

// AuthResponse object - holds token info
type Organization struct {
	UserID string `json:"user_id"`
	UserName string `json:"user_name"`
	Name string `json:"name"`
	DisplayName string `json:"display_name"`
	OrgType string `json:"org_type"`
}
