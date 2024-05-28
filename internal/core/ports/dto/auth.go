package dto

type RegisterRequestDto struct {
	Nickname   string `json:"nickname,omitempty"   binding:"required"`
	Email      string `json:"email,omitempty"      binding:"required,email"`
	Phone      string `json:"phone,omitempty"      binding:"required"`
	LastName   string `json:"lastName,omitempty"   binding:"required"`
	Name       string `json:"name,omitempty"       binding:"required"`
	Patronymic string `json:"patronymic,omitempty"`
	Password   string `json:"password,omitempty"   binding:"required,min=8"`
}

type LoginRequestDto struct {
	Login    string `json:"login"    binding:"required"`
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
