package errors

type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return e.Message
}

type MappingError struct {
	Message string
}

func (e *MappingError) Error() string {
	return e.Message
}

type TokenGenerationError struct {
	Message string
}

func (e *TokenGenerationError) Error() string {
	return e.Message
}

type TokenParsingError struct {
	Message string
}

func (e *TokenParsingError) Error() string {
	return e.Message
}

type AlreadyExistsError struct {
	Message string
}

func (e *AlreadyExistsError) Error() string {
	return e.Message
}

type BodyMappingError struct {
	Message string
}

func (e *BodyMappingError) Error() string {
	return e.Message
}

type CookieGettingError struct {
	Message string
}

func (e *CookieGettingError) Error() string {
	return e.Message
}

type RefreshError struct {
	Message string
}

func (e *RefreshError) Error() string {
	return e.Message
}

type LoginOrPasswordDoNotMatchError struct {
	Message string
}

func (e *LoginOrPasswordDoNotMatchError) Error() string {
	return e.Message
}
