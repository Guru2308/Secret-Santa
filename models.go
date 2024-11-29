package main

type RegisteredUser struct {
	ID       uint   `gorm:"primaryKey"`
	Email    string `gorm:"uniqueIndex"`
	Password string
}

type UserConnection struct {
	ID      uint `gorm:"primaryKey"`
	SantaID uint `gorm:"not null"`    // The user this user is gifting to
	ChildID uint `gorm:"not null"`    // The user this user is receiving a gift from
}

type NamesRequest struct {
	Names []string `json:"names"`
}
