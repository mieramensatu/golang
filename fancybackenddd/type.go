package peda

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type GeometryPolygon struct {
	Coordinates [][][]float64 `json:"coordinates" bson:"coordinates"`
	Type        string        `json:"type" bson:"type"`
}

type GeometryLineString struct {
	Coordinates [][]float64 `json:"coordinates" bson:"coordinates"`
	Type        string      `json:"type" bson:"type"`
}

type GeometryPoint struct {
	Coordinates []float64 `json:"coordinates" bson:"coordinates"`
	Type        string    `json:"type" bson:"type"`
}

type GeoJsonLineString struct {
	Type       string             `json:"type" bson:"type"`
	Properties Properties         `json:"properties" bson:"properties"`
	Geometry   GeometryLineString `json:"geometry" bson:"geometry"`
}

type GeoJsonPolygon struct {
	Type       string          `json:"type" bson:"type"`
	Properties Properties      `json:"properties" bson:"properties"`
	Geometry   GeometryPolygon `json:"geometry" bson:"geometry"`
}

type Geometry struct {
	Coordinates interface{} `json:"coordinates" bson:"coordinates"`
	Type        string      `json:"type" bson:"type"`
}
type GeoJson struct {
	Type       string     `json:"type" bson:"type"`
	Properties Properties `json:"properties" bson:"properties"`
	Geometry   Geometry   `json:"geometry" bson:"geometry"`
}

type Properties struct {
	Name string `json:"name" bson:"name"`
}

type User struct {
	Username    string `json:"username" bson:"username"`
	Password    string `json:"password" bson:"password,omitempty"`
	Role        string `json:"role,omitempty" bson:"role,omitempty"`
	Token       string `json:"token,omitempty" bson:"token,omitempty"`
	Private     string `json:"private,omitempty" bson:"private,omitempty"`
	Publick     string `json:"publick,omitempty" bson:"publick,omitempty"`
	No_whatsapp string `json:"no_whatsapp,omitempty" bson:"no_whatsapp,omitempty"`
}

type UserToken struct {
	Username User `json:"username" bson:"username"`
}

type Payload struct {
	User string    `json:"user"`
	Role string    `json:"role"`
	Exp  time.Time `json:"exp"`
	Iat  time.Time `json:"iat"`
	Nbf  time.Time `json:"nbf"`
}

type Credential struct {
	Status   bool   `json:"status" bson:"status"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Message  string `json:"message,omitempty" bson:"message,omitempty"`
	Username string `json:"username,omitempty" bson:"username,omitempty"`
}

type Product struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" `
	Nomorid     int                `json:"nomorid" bson:"nomorid"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       int                `json:"price" bson:"price"`
	Stock       int                `json:"stock" bson:"stock"`
	Size        string             `json:"size" bson:"size"`
	Image       string             `json:"image" bson:"image"`
	Status      bool               `json:"status" bson:"status"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}

type Content struct {
	ID          int    `json:"id" bson:"id" `
	Content     string `json:"content" bson:"content"`
	Image       string `json:"image" bson:"image"`
	Description string `json:"description" bson:"description"`
	Status      bool   `json:"status" bson:"status"`
}

type Blog struct {
	ID                int    `json:"id" bson:"id"`
	Content           string `json:"content_one" bson:"content_one"`
	Content_two       string `json:"content_two" bson:"content_two"`
	Image             string `json:"image" bson:"image"`
	Title             string `json:"title" bson:"title"`
	Title_two         string `json:"title_two" bson:"title_two"`
	Description       string `json:"description" bson:"description"`
	Description_twoo  string `json:"description_two" bson:"description_two"`
	Description_three string `json:"description_3" bson:"description_3"`
	Status            bool   `json:"status" bson:"status"`
}

type Tags struct {
	Tags string `json:"tags" bson:"tags"`
}

type Category struct {
	Category string `json:"category" bson:"category"`
	Status   bool   `json:"status" bson:"status"`
}

type Comment struct {
	ID        int    `json:"id" bson:"id"`
	Username  string `json:"username" bson:"username"`
	Answer    string `json:"comment" bson:"comment"`
	Questions string `json:"questions" bson:"questions"`
	Tanggal   string `json:"tanggal" bson:"tanggal"`
	Status    bool   `json:"status" bson:"status"`
}

type Share struct {
	Share  string `json:"share" bson:"share"`
	Status bool   `json:"status" bson:"status"`
}

type EventGlobal struct {
	ID          int       `json:"id" bson:"id"`
	Title       string    `json:"title" bson:"title"`
	Description string    `json:"description" bson:"description"`
	Tanggal     string    `json:"tanggal" bson:"tanggal"`
	Image       string    `json:"image" bson:"image"`
	Harga       int       `json:"harga" bson:"harga"`
	Content     []Content `json:"content" bson:"content"`
	Product     []Product `json:"product" bson:"product"`
	Status      bool      `json:"status" bson:"status"`
}

type Event struct {
	ID          int       `json:"id" bson:"id"`
	Title       string    `json:"title" bson:"title"`
	Description string    `json:"description" bson:"description"`
	Tanggal     string    `json:"tanggal" bson:"tanggal"`
	Image       string    `json:"image" bson:"image"`
	Harga       int       `json:"harga" bson:"harga"`
	LinkYoutube string    `json:"linkyoutube" bson:"linkyoutube"`
	Content     []Content `json:"content" bson:"content"`
	Product     []Product `json:"product" bson:"product"`
	Status      bool      `json:"status" bson:"status"`
}

type About struct {
	ID          int       `json:"id" bson:"id"`
	Title       string    `json:"title" bson:"title"`
	Description string    `json:"description" bson:"description"`
	Image       string    `json:"image" bson:"image"`
	Content     []Content `json:"content" bson:"content"`
	Product     []Product `json:"product" bson:"product"`
	Status      bool      `json:"status" bson:"status"`
}

type Gallery struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
	Status      bool   `json:"status" bson:"status"`
}

type Contack struct {
	ID      int    `json:"id" bson:"id"`
	Name    string `json:"title" bson:"title"`
	Subject string `json:"description" bson:"description"`
	Message string `json:"image" bson:"image"`
	Email   string `json:"email" bson:"email"`
	Phone   string `json:"phone" bson:"phone"`
	Status  bool   `json:"status" bson:"status"`
}

type Iklan struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
	Status      bool   `json:"status" bson:"status"`
}

type Location struct {
	Type        string      `bson:"type"`
	Coordinates [][]float64 `bson:"coordinates"`
	CRS         struct {
		Type       string `bson:"type"`
		Properties struct {
			Name string `bson:"name"`
		} `bson:"properties"`
	} `bson:"crs"`
}

type Query struct {
	LocationField struct {
		GeoIntersects struct {
			Geometry Location `bson:"$geometry"`
		} `bson:"$geoIntersects"`
	} `bson:"locationField"`
}

type Testing struct {
	ID          int       `json:"id" bson:"id"`
	Title       string    `json:title bson:"title"`
	Description string    `json:description bson:"description"`
	Image       string    `json:image bson:"image"`
	Status      bool      `json:status bson:"status"`
	Nama        string    `json:nama bson:"nama"`
	alamat      string    `json:alamat bson:"alamat"`
	tanggal     time.Time `json:tanggal bson:"tanggal"`
}
