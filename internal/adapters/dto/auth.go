package dto

type RegisterRequestDto struct {
	Nickname string `json:"nickname" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequestDto struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type RefreshRequestDto struct {
	RefreshToken string
}

type LogoutRequestDto struct {
	RefreshToken string
}

type AuthResponseDto struct {
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}
