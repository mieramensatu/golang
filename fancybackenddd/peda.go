package peda

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aiteung/atapi"
	"github.com/aiteung/atdb"
	"github.com/aiteung/atmessage"
	"github.com/whatsauth/wa"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

// func GCFHandler(MONGOCONNSTRINGENV, dbname, collectionname string) string {
// 	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
// 	datagedung := GetAllUser(mconn, collectionname)
// 	return GCFReturnStruct(datagedung)
// }

func GCFFindUserByID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	user := FindUser(mconn, collectionname, datauser)
	return GCFReturnStruct(user)
}

func GCFFindUserByName(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Jika username kosong, maka respon "false" dan data tidak ada
	if datauser.Username == "" {
		return "false"
	}

	// Jika ada username, mencari data pengguna
	user := FindUserUser(mconn, collectionname, datauser)

	// Jika data pengguna ditemukan, mengembalikan data pengguna dalam format yang sesuai
	if user != (User{}) {
		return GCFReturnStruct(user)
	}

	// Jika tidak ada data pengguna yang ditemukan, mengembalikan "false" dan data tidak ada
	return "false"
}

func GCFDeleteHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	DeleteUser(mconn, collectionname, datauser)
	return GCFReturnStruct(datauser)
}

func GCFUpdateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	ReplaceOneDoc(mconn, collectionname, bson.M{"username": datauser.Username}, datauser)
	return GCFReturnStruct(datauser)
}

// add encrypt password to database and tokenstring
// func GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {

// 	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
// 	var datauser User
// 	err := json.NewDecoder(r.Body).Decode(&datauser)
// 	if err != nil {
// 		return err.Error()
// 	}
// 	CreateNewUserRole(mconn, collectionname, datauser)
// 	return GCFReturnStruct(datauser)
// }

func GCFCreateHandlerTokenPaseto(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword
	CreateNewUserRole(mconn, collectionname, datauser)
	tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err.Error()
	}
	datauser.Token = tokenstring
	return GCFReturnStruct(datauser)
}

func GCFCreateAccountAndToken(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword
	CreateUserAndAddedToeken(PASETOPRIVATEKEYENV, mconn, collectionname, datauser)
	return GCFReturnStruct(datauser)
}
func GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Hash the password before storing it
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword

	createErr := CreateNewUserRole(mconn, collectionname, datauser)
	fmt.Println(createErr)

	return GCFReturnStruct(datauser)
}
func GFCPostHandlerUser(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false

	// Mendapatkan data yang diterima dari permintaan HTTP POST
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Menggunakan variabel MONGOCONNSTRINGENV untuk string koneksi MongoDB
		mongoConnStringEnv := MONGOCONNSTRINGENV

		mconn := SetConnection(mongoConnStringEnv, dbname)

		// Lakukan pemeriksaan kata sandi menggunakan bcrypt
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			Response.Message = "Selamat Datang"
		} else {
			Response.Message = "Password Salah"
		}
	}

	// Mengirimkan respons sebagai JSON
	responseJSON, _ := json.Marshal(Response)
	return string(responseJSON)
}

func GCFPostHandler(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func GCFReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

// product
func GCFGetAllProduct(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datagedung := GetAllProduct(mconn, collectionname)
	return GCFReturnStruct(datagedung)
}

func GCFGetAllContentBy(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacontent := GetAllContent(mconn, collectionname)
	return GCFReturnStruct(datacontent)
}

func GCFCreateProduct(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) Credential {
	var Response Credential
	Response.Status = false

	// Retrieve the "PUBLICKEY" from the request headers
	publicKey := r.Header.Get("PUBLICKEY")
	if publicKey == "" {
		Response.Message = "Missing PUBLICKEY in headers"
	} else {
		// Process the request with the "PUBLICKEY"
		mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
		var dataproduct Product
		err := json.NewDecoder(r.Body).Decode(&dataproduct)
		if err != nil {
			Response.Message = "Error parsing application/json: " + err.Error()
		} else {
			CreateNewProduct(mconn, dbname, Product{
				Nomorid:     dataproduct.Nomorid,
				Name:        dataproduct.Name,
				Description: dataproduct.Description,
				Price:       dataproduct.Price,
				Stock:       dataproduct.Stock,
				Size:        dataproduct.Size,
				Image:       dataproduct.Image,
			})
			Response.Status = true
			Response.Message = "Berhasil"
			// No token generation here
		}
	}
	return Response
}

func GCFLoginTest(username, password, MONGOCONNSTRINGENV, dbname, collectionname string) bool {
	// Membuat koneksi ke MongoDB
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Mencari data pengguna berdasarkan username
	filter := bson.M{"username": username}
	collection := collectionname
	res := atdb.GetOneDoc[User](mconn, collection, filter)

	// Memeriksa apakah pengguna ditemukan dalam database
	if res == (User{}) {
		return false
	}

	// Memeriksa apakah kata sandi cocok
	return CheckPasswordHash(password, res.Password)
}

// Content

func GCFCreateContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datacontent Content
	err := json.NewDecoder(r.Body).Decode(&datacontent)
	if err != nil {
		return err.Error()
	}

	CreateNewContent(mconn, collectionname, datacontent)
	// setelah create content munculkan response berhasil dan 200

	if CreateResponse(true, "Berhasil", datacontent) != (Response{}) {
		return GCFReturnStruct(CreateResponse(true, "success Create Data Content", datacontent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Data Content", datacontent))
	}
}

func GCFDeleteHandlerContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var contentdata Content
	err := json.NewDecoder(r.Body).Decode(&contentdata)
	if err != nil {
		return err.Error()
	}
	DeleteContent(mconn, collectionname, contentdata)
	return GCFReturnStruct(contentdata)
}

func GCFUpdatedContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var contentdata Content
	err := json.NewDecoder(r.Body).Decode(&contentdata)
	if err != nil {
		return err.Error()
	}
	ReplaceContent(mconn, collectionname, bson.M{"id": contentdata.ID}, contentdata)
	return GCFReturnStruct(contentdata)
}

func GCFCreateNewBlog(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var blogdata Blog
	err := json.NewDecoder(r.Body).Decode(&blogdata)
	if err != nil {
		return err.Error()
	}
	CreateNewBlog(mconn, collectionname, blogdata)
	return GCFReturnStruct(blogdata)
}

func GCFFindContentAllID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datacontent
	var datacontent Content

	// Membaca data JSON dari permintaan HTTP ke dalam datacontent
	err := json.NewDecoder(r.Body).Decode(&datacontent)
	if err != nil {
		return err.Error()
	}

	// Memanggil fungsi FindContentAllId
	content := FindContentAllId(mconn, collectionname, datacontent)

	// Mengembalikan hasil dalam bentuk JSON
	return GCFReturnStruct(content)
}

func GCFFindBlogAllID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datacontent
	var datablog Blog

	// Membaca data JSON dari permintaan HTTP ke dalam datacontent
	err := json.NewDecoder(r.Body).Decode(&datablog)
	if err != nil {
		return err.Error()
	}

	// Memanggil fungsi FindContentAllId
	blog := GetIDBlog(mconn, collectionname, datablog)

	// Mengembalikan hasil dalam bentuk JSON
	return GCFReturnStruct(blog)
}

func GCFGetAllBlog(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datablog := GetAllBlogAll(mconn, collectionname)
	return GCFReturnStruct(datablog)
}

func GCFCreateTokenAndSaveToDB(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) (string, error) {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datauser
	var datauser User

	// Membaca data JSON dari permintaan HTTP ke dalam datauser
	if err := json.NewDecoder(r.Body).Decode(&datauser); err != nil {
		return "", err // Mengembalikan kesalahan langsung
	}

	// Generate a token for the user
	tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return "", err // Mengembalikan kesalahan langsung
	}
	datauser.Token = tokenstring

	// Simpan pengguna ke dalam basis data
	if err := atdb.InsertOneDoc(mconn, collectionname, datauser); err != nil {
		return tokenstring, nil // Mengembalikan kesalahan langsung
	}

	return tokenstring, nil // Mengembalikan token dan nil untuk kesalahan jika sukses
}
func GCFCreteRegister(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	CreateUser(mconn, collectionname, userdata)
	return GCFReturnStruct(userdata)
}

func GCFLoginAfterCreate(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		tokenstring, err := watoken.Encode(userdata.Username, os.Getenv("PASETOPRIVATEKEYENV"))
		if err != nil {
			return err.Error()
		}
		userdata.Token = tokenstring
		return GCFReturnStruct(userdata)
	} else {
		return "Password Salah"
	}
}

func GCFLoginAfterCreater(MONGOCONNSTRINGENV, dbname, collectionname, privateKeyEnv string, r *http.Request) (string, error) {
	// Ambil data pengguna dari request, misalnya dari body JSON atau form data.
	var userdata User
	// Implement the logic to extract user data from the request (r) here.

	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Lakukan otentikasi pengguna yang baru saja dibuat.
	token, err := AuthenticateUserAndGenerateToken(privateKeyEnv, mconn, collectionname, userdata)
	if err != nil {
		return "", err
	}
	return token, nil
}

func GCFLoginAfterCreatee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, return a success message or some other response.
		return "Login successful"

	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFLoginAfterCreateee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, construct and return the GCFReturnStruct.
		response := CreateResponse(true, "Berhasil Login", userdata)
		return GCFReturnStruct(response) // Return GCFReturnStruct directly
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}
func GCFLoginAfterCreateeee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, return a success message or some other response.
		return GCFReturnStruct(userdata)
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFCreteCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	err := json.NewDecoder(r.Body).Decode(&commentdata)
	if err != nil {
		return err.Error()
	}

	if err := CreateComment(mconn, collectionname, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Succes Create Comment", commentdata))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Comment", commentdata))
	}
}

func GCFGetAllComment(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacomment := GetAllComment(mconn, collectionname)
	if datacomment != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Comment", datacomment))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Comment", datacomment))
	}
}
func GFCUpadatedCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	err := json.NewDecoder(r.Body).Decode(&commentdata)
	if err != nil {
		return err.Error()
	}

	if err := UpdatedComment(mconn, collectionname, bson.M{"id": commentdata.ID}, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Updated Comment", commentdata))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Updated Comment", commentdata))
	}
}

func GCFDeletedCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	if err := json.NewDecoder(r.Body).Decode(&commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(false, "Failed to process request", commentdata))
	}

	if err := DeleteComment(mconn, collectionname, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Successfully deleted comment", commentdata))
	}

	return GCFReturnStruct(CreateResponse(false, "Failed to delete comment", commentdata))
}

// get all
func GCFGetAllEvent(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataevent := GetAllEventGlobal(mconn, collectionname)
	if dataevent != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Event", dataevent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Event", dataevent))
	}
}
func GCFHandler(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datagedung := GetAllBangunanLineString(mconn, collectionname)
	if datagedung != nil {
		return GCFReturnStruct(CreateResponse(false, "Succes Get All Bangunan", datagedung))
	} else {
		return GCFReturnStruct(CreateResponse(true, "Failed Get All Bangunan", datagedung))

	}
}

func GCFCretatedEventGlobal(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var eventglobaldata EventGlobal
	err := json.NewDecoder(r.Body).Decode(&eventglobaldata)
	if err != nil {
		return err.Error()
	}

	if err := CreateEventGlobal(mconn, collectionname, eventglobaldata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Create Event Global", eventglobaldata))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Event Global", eventglobaldata))
	}
}

func GCFAllGlobalID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var eventglobaldata EventGlobal
	err := json.NewDecoder(r.Body).Decode(&eventglobaldata)
	if err != nil {
		return err.Error()
	}

	eventglobal := GetAllEventGlobalId(mconn, collectionname, eventglobaldata)
	if eventglobal != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Event Global", eventglobal))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Event Global", eventglobal))
	}
}

func GCFGetAllUser(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datauser := GetAllUser(mconn, collectionname)
	if datauser != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All User", datauser))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All User", datauser))
	}
}

func GCFCreatePostLineStringg(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}

	// Mengambil nilai header PASETO dari permintaan HTTP
	pasetoValue := r.Header.Get("PASETOPRIVATEKEYENV")

	// Disini Anda dapat menggunakan nilai pasetoValue sesuai kebutuhan Anda
	// Misalnya, menggunakannya untuk otentikasi atau enkripsi.
	// Contoh sederhana menambahkan nilainya ke dalam pesan respons:
	response := GCFReturnStruct(geojsonline)
	response += " PASETO value: " + pasetoValue

	PostLinestring(mconn, collection, geojsonline)
	return response
}

func GCFCreatePostLineString(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}
	PostLinestring(mconn, collection, geojsonline)
	return GCFReturnStruct(geojsonline)
}

func GCFLoginFixx(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}

	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, construct and return the GCFReturnStruct.
		userMap := map[string]interface{}{
			"Username": userdata.Username,
			"Password": userdata.Password,
			"Private":  userdata.Private,
			"Publick":  userdata.Publick,
		}
		response := CreateResponse(true, "Berhasil Login", userMap)
		return GCFReturnStruct(response) // Return GCFReturnStruct directly
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFLoginFixxx(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}

	foundUser, isValid := IsPasswordValidd(mconn, collectionname, userdata)
	if isValid {
		// Password is valid, construct and return the GCFReturnStruct.
		response := CreateResponse(true, "Berhasil Login", foundUser)
		return GCFReturnStruct(response)
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFCreateProducttWithpublickey(MONGOCONNSTRINGENV, dbname, collectionname string, publickey string, r *http.Request) Credential {
	var Response Credential
	Response.Status = false

	// Retrieve the "Login" token from the request headers
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		Response.Message = "Missing Login token in headers"
	} else {
		// Process the request with the "Login" token
		mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
		var dataproduct Product
		err := json.NewDecoder(r.Body).Decode(&dataproduct)
		if err != nil {
			Response.Message = "Error parsing application/json: " + err.Error()
		} else {
			// Assuming `tokenstr` is defined or retrieved from somewhere
			// Check if the token is valid
			Payload, err := IsTokenValid(publickey, tokenlogin)
			if err == nil {
				Response.Message = "Token Login tidak valid"
			} else if Payload.Role != "admin" {
				// Create a new product if the token is valid
				CreateNewProduct(mconn, dbname, Product{
					Nomorid:     dataproduct.Nomorid,
					Name:        dataproduct.Name,
					Description: dataproduct.Description,
					Price:       dataproduct.Price,
					Stock:       dataproduct.Stock,
					Size:        dataproduct.Size,
					Image:       dataproduct.Image,
				})
				Response.Status = true
				Response.Message = "Product creation successful"
			} else {
				Response.Message = "Invalid token"
			}
		}
	}
	return Response
}

func GCFCreateProducttWithpublickeyFix(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) Credential {
	var Response Credential
	Response.Status = false

	// Retrieve the "Login" token from the request headers
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		Response.Message = "Missing Login token in headers"
	} else {
		// Process the request with the "Login" token
		mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
		var dataproduct Product
		err := json.NewDecoder(r.Body).Decode(&dataproduct)
		if err != nil {
			Response.Message = "Error parsing application/json: " + err.Error()
		} else {
			// Assuming `tokenstr` is defined or retrieved from somewhere
			// Check if the token is valid
			if r.Header.Get("Login") == os.Getenv("PASETOPRIVATEKEYENV") {
				// Create a new product if the token is valid
				CreateNewProduct(mconn, dbname, Product{
					Nomorid:     dataproduct.Nomorid,
					Name:        dataproduct.Name,
					Description: dataproduct.Description,
					Price:       dataproduct.Price,
					Stock:       dataproduct.Stock,
					Size:        dataproduct.Size,
					Image:       dataproduct.Image,
				})
				Response.Status = true
				Response.Message = "Product creation successful"
			} else {
				Response.Message = "Invalid token"
			}
		}
	}
	return Response
}

// <--- ini product --->

// product post

func GCFCreateProductt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collproduct string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User
	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataproduct Product
				err := json.NewDecoder(r.Body).Decode(&dataproduct)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateNewProduct(mconn, collproduct, Product{
						Nomorid:     dataproduct.Nomorid,
						Name:        dataproduct.Name,
						Description: dataproduct.Description,
						Price:       dataproduct.Price,
						Stock:       dataproduct.Stock,
						Size:        dataproduct.Size,
						Image:       dataproduct.Image,
						Status:      dataproduct.Status,
					})
					response.Status = true
					response.Message = "Product creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}
func GCFEndCodepaseto(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	// Mengecek user lewat private key
	gettoken := r.Header.Get("private")
	if gettoken == "" {
		response.Message = "Nama token tidak ada"
	} else {
		// Decode nama lewat token
		checktoken := watoken.DecodeGetId(os.Getenv("private"), gettoken)
		authdata.Private = checktoken
		if checktoken == "" {
			response.Message = "Nama token tidak valid"
		} else {
			// Cek keberadaan user di database berdasarkan private key
			authUser, err := FindUserByPrivate(mconn, collectionname, authdata)
			if err != nil {
				// Handle the error, e.g., log it or set an appropriate response message
				response.Message = "Error while checking user: " + err.Error()
			} else if authUser.Private == "" {
				response.Message = "User tidak ditemukan"
			} else {
				// Authentication successful, set the response status and message
				response.Status = true
				response.Message = "User berhasil diotentikasi"
				GCFReturnStruct(CreateResponse(true, "Success Update Product", authUser))
			}
		}
	}

	// You may want to return a JSON response or something similar
	// For now, assuming Credential is a struct with fields Status, Message, UserName, and UserRole
	return response.Message
}

// delete product
func GCFDeleteProduct(publickey, MONGOCONNSTRINGENV, dbname, colluser, collproduct string, r *http.Request) string {

	var respon Credential
	respon.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		respon.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			respon.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataproduct Product
				err := json.NewDecoder(r.Body).Decode(&dataproduct)
				if err != nil {
					respon.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteProduct(mconn, collproduct, dataproduct)
					respon.Status = true
					respon.Message = "Product Delete successful"
				}
			} else {
				respon.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(respon)
}

// update product

func GCFUpdateProduct(publickey, MONGOCONNSTRINGENV, dbname, colluser, collproduct string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in Headers"
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataproduct Product
				err := json.NewDecoder(r.Body).Decode(&dataproduct)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				} else {
					UpdatedProduct(mconn, collproduct, bson.M{"id": dataproduct.ID}, dataproduct)
					response.Status = true
					response.Message = "Product Updated Succescfull"
					GCFReturnStruct(CreateResponse(true, "Success Update Product", dataproduct))
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}

		}
	}
	return GCFReturnStruct(response)
}

// get all product
func GCFGetAllProductt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataproduct := GetAllProduct(mconn, collectionname)
	if dataproduct != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Product", dataproduct))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Product", dataproduct))
	}
}

// get all product by id
func GCFGetAllProducttID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var dataproduct Product
	err := json.NewDecoder(r.Body).Decode(&dataproduct)
	if err != nil {
		return err.Error()
	}

	product := GetAllProductID(mconn, collectionname, dataproduct)
	if product != (Product{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Product", dataproduct))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Product", dataproduct))
	}
}

func GCFGetAllPrivateID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var dataproduct User
	err := json.NewDecoder(r.Body).Decode(&dataproduct)
	if err != nil {
		return fmt.Sprintf("Error decoding request body: %s", err)
	}

	product := FindPrivate(mconn, collectionname, dataproduct)
	if product != (User{}) {
		// Password is valid, construct and return the GCFReturnStruct.
		// userMap := map[string]interface{}{"username": dataproduct.Username}
		response := CreateResponse(true, "Berhasil Login", product.Username)
		return GCFReturnStruct(response) // Return GCFReturnStruct directly
	} else {
		// Password is not valid, return an error message.
		return "Nama Di token tidak ada"
	}
}

func GCFPostHandlerrr(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				// CreateResponse(true, "Berhasil Login", tokenstring)
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
				Response.Username = datauser.Username
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func v(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Message = datauser.Username
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

// <--- ini content --->

func Authorization(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	var auth User
	response.Status = false

	// Extract token from the request header
	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	// Decode token values
	tokenname := watoken.DecodeGetId(os.Getenv(publickey), header)

	// Create User struct with the decoded username
	auth.Username = tokenname

	// Check if decoding results are valid
	if tokenname == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	// Check if the user exists
	if !usernameExists(mongoenv, dbname, auth) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}
	// Successful token decoding and user validation
	response.Message = "Berhasil decode token"
	response.Status = true
	response.Username = tokenname
	return GCFReturnStruct(response)
}

// content post
func GCFCreateContentt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontet Content
				err := json.NewDecoder(r.Body).Decode(&datacontet)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				} else {
					CreateNewContent(mconn, collcontent, Content{
						ID:          datacontet.ID,
						Content:     datacontet.Content,
						Description: datacontet.Description,
						Image:       datacontet.Image,
						Status:      datacontet.Status,
					})
					response.Status = true
					response.Message = "Content creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete content
func GCFDeleteContent(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontent Content
				err := json.NewDecoder(r.Body).Decode(&datacontent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteContent(mconn, collcontent, datacontent)
					response.Status = true
					response.Message = "Content Delete successful"
					CreateResponse(true, "Success Delete Content", datacontent)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update content
func GCFUpdateContent(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontent Content
				err := json.NewDecoder(r.Body).Decode(&datacontent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					UpdatedContentt(mconn, collcontent, bson.M{"id": datacontent.ID}, datacontent)
					response.Status = true
					response.Message = "Content Updated Succescfull"
					CreateResponse(true, "Success Update Content", datacontent)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// get all content
func GCFGetAllContentt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacontent := GetAllContent(mconn, collectionname)
	if datacontent != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Content", datacontent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Content", datacontent))
	}
}

// get all content by id
func GCFGetAllContenttID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var datacontent Content
	err := json.NewDecoder(r.Body).Decode(&datacontent)
	if err != nil {
		return err.Error()
	}

	content := GetIDContentt(mconn, collectionname, datacontent)
	if content != (Content{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Content", datacontent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Content", datacontent))
	}
}

// <--- ini blog --->

// blog post
func GCFCreateBlogg(publickey, MONGOCONNSTRINGENV, dbname, colluser, collblog string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {

				var datablog Blog
				err := json.NewDecoder(r.Body).Decode(&datablog)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateNewBlog(mconn, collblog, Blog{
						ID:                datablog.ID,
						Content:           datablog.Content,
						Content_two:       datablog.Content_two,
						Image:             datablog.Image,
						Title:             datablog.Title,
						Title_two:         datablog.Title_two,
						Description:       datablog.Description,
						Description_twoo:  datablog.Description_twoo,
						Description_three: datablog.Description_three,
						Status:            datablog.Status,
					})
					response.Status = true
					response.Message = "Blog creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete blog
func GCFDeleteBlog(publickey, MONGOCONNSTRINGENV, dbname, colluser, collblog string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datablog Blog
				err := json.NewDecoder(r.Body).Decode(&datablog)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteBlog(mconn, collblog, datablog)
					response.Status = true
					response.Message = "Blog Delete successful"
					CreateResponse(true, "Success Delete Blog", datablog)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update blog
func GCFUpdateBlog(publickey, MONGOCONNSTRINGENV, dbname, colluser, collblog string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datablog Blog

				err := json.NewDecoder(r.Body).Decode(&datablog)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				}
				UpdatedBlog(mconn, collblog, bson.M{"id": datablog.ID}, datablog)
				response.Status = true
				response.Message = "Blog Updated Succescfull"
				CreateResponse(true, "Success Update Blog", datablog)
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}

		}
	}
	return GCFReturnStruct(response)
}

// get all blog
func GCFGetAllBlogg(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datablog := GetAllBlogAll(mconn, collectionname)
	if datablog != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Blog", datablog))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Blog", datablog))
	}
}

// <--- ini comment --->

// comment post

func GCFCreateCommentt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcomment string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacomment Comment
				err := json.NewDecoder(r.Body).Decode(&datacomment)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateComment(mconn, collcomment, datacomment)
					response.Status = true
					response.Message = "Comment creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)

}

// delete comment
func GCFDeleteCommentt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcomment string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacomment Comment
				err := json.NewDecoder(r.Body).Decode(&datacomment)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				}
				DeleteComment(mconn, collcomment, datacomment)
				response.Status = true
				response.Message = "Comment Delete successful"
				CreateResponse(true, "Success Delete Comment", datacomment)
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update comment
func GCFUpdateCommentt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcomment string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in Headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacomment Comment
				err := json.NewDecoder(r.Body).Decode(&datacomment)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				}

				UpdatedComment(mconn, collcomment, bson.M{"id": datacomment.ID}, datacomment)
				response.Status = true
				response.Message = "Comment Updated Succescfull"
				CreateResponse(true, "Success Update Comment", datacomment)
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}

		}
	}
	return GCFReturnStruct(response)
}

// get all comment
func GCFGetAllCommentt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacomment := GetAllComment(mconn, collectionname)
	if datacomment != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Comment", datacomment))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Comment", datacomment))
	}
}

// get all comment by id
func GCFGetAllCommenttID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var datacomment Comment
	err := json.NewDecoder(r.Body).Decode(&datacomment)
	if err != nil {
		return err.Error()
	}

	comment := GetIDComment(mconn, collectionname, datacomment)
	if comment != (Comment{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Comment", datacomment))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Comment", datacomment))
	}
}

// <--- ini event global--->

// event global post
func GCFCreateEventGlobal(publickey, MONGOCONNSTRINGENV, dbname, colluser, colleventglobal string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in Headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)

		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {

			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataevent EventGlobal
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				}
				CreateEventGlobal(mconn, colleventglobal, EventGlobal{
					ID:          dataevent.ID,
					Title:       dataevent.Title,
					Description: dataevent.Description,
					Tanggal:     dataevent.Tanggal,
					Content:     dataevent.Content,
					Image:       dataevent.Image,
					Harga:       dataevent.Harga,
					Product:     dataevent.Product,
					Status:      dataevent.Status,
				})
				response.Status = true
				response.Message = "Event Global creation successful"
			} else {
				response.Message = "ANDA BUKAN ADMIN"

			}
		}
	}
	return GCFReturnStruct(response)
}

// delete event global
func GCFDeleteEventGlobal(publickey, MONGOCONNSTRINGENV, dbname, colluser, colleventglobal string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in Headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {

				var dataevent EventGlobal
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				}
				DeleteEventGlobal(mconn, colleventglobal, dataevent)
				response.Status = true
				response.Message = "Event Global Delete successful"
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update event global
func GCFUpdateEventGlobal(publickey, MONGOCONNSTRINGENV, dbname, colluser, colleventglobal string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataevent EventGlobal
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					UpdatedEventGlobal(mconn, colleventglobal, bson.M{"id": dataevent.ID}, dataevent)
					response.Status = true
					response.Message = "Event Global Updated Succescfull"
					CreateResponse(true, "Success Update Event Global", dataevent)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// get all event global
func GCFGetAllEventGlobal(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataevent := GetAllEventGlobal(mconn, collectionname)
	if dataevent != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Event Global", dataevent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Event Global", dataevent))
	}
}

// get all event global by id
func GCFGetAllEventGlobalID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var dataevent EventGlobal
	err := json.NewDecoder(r.Body).Decode(&dataevent)
	if err != nil {
		return err.Error()
	}

	eventglobal := GetAllEventGlobalId(mconn, collectionname, dataevent)
	if eventglobal != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Event Global", eventglobal))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Event Global", eventglobal))
	}
}

// <--- ini event --->
// event post
func GCFCreateEventt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collevent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataevent Event
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateEvent(mconn, collevent, Event{
						ID:          dataevent.ID,
						Title:       dataevent.Title,
						Description: dataevent.Description,
						Tanggal:     dataevent.Tanggal,
						Content:     dataevent.Content,
						Image:       dataevent.Image,
						Harga:       dataevent.Harga,
						Product:     dataevent.Product,
						LinkYoutube: dataevent.LinkYoutube,
						Status:      dataevent.Status,
					})
					response.Status = true
					response.Message = "Event creation successful"

				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete event
func GCFDeleteEventt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collevent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataevent Event
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				}
				DeleteEvent(mconn, collevent, dataevent)
				response.Status = true
				response.Message = "Event Delete successful"

			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update event
func GCFUpdateEventt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collevent string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {

				var dataevent Event
				err := json.NewDecoder(r.Body).Decode(&dataevent)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				}
				UpdatedEvent(mconn, collevent, bson.M{"id": dataevent.ID}, dataevent)
				response.Status = true
				response.Message = "Event Updated Succescfull"

			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// get all event
func GCFGetAllEventt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataevent := GetAllEvent(mconn, collectionname)
	if dataevent != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Event", dataevent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Event", dataevent))
	}
}

// get all event by id
// func GCFGetAllEventtID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
// 	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

// 	var dataevent Event
// 	err := json.NewDecoder(r.Body).Decode(&dataevent)
// 	if err != nil {
// 		return err.Error()
// 	}

// 	event := GetIDEvent(mconn, collectionname, dataevent)
// 	if event != (Event{}) {
// 		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Event", dataevent))
// 	} else {
// 		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Event", dataevent))
// 	}
// }

// <--- ini about --->

// about post
func GCFCreateAboutt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collabout string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {

				var dataabout About
				err := json.NewDecoder(r.Body).Decode(&dataabout)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateAbout(mconn, collabout, About{
						ID:          dataabout.ID,
						Title:       dataabout.Title,
						Description: dataabout.Description,
						Content:     dataabout.Content,
						Image:       dataabout.Image,
						Product:     dataabout.Product,
						Status:      dataabout.Status,
					})
					response.Status = true
					response.Message = "About creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)

}

// delete about
func GCFDeleteAboutt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collabout string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {

				var dataabout About
				err := json.NewDecoder(r.Body).Decode(&dataabout)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteAbout(mconn, collabout, dataabout)
					response.Status = true
					response.Message = "About Delete successful"
					CreateResponse(true, "Success Delete About", dataabout)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update about
func GCFUpdateAboutt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collabout string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataabout About
				err := json.NewDecoder(r.Body).Decode(&dataabout)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					UpdatedAbout(mconn, collabout, bson.M{"id": dataabout.ID}, dataabout)
					response.Status = true
					response.Message = "About Updated Succescfull"
					CreateResponse(true, "Success Update About", dataabout)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// get all about
func GCFGetAllAboutt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataabout := GetAllAbout(mconn, collectionname)
	if dataabout != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All About", dataabout))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All About", dataabout))
	}
}

// // get all about by id
// func GCFGetAllAbouttID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
// 	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

// 	var dataabout About
// 	err := json.NewDecoder(r.Body).Decode(&dataabout)
// 	if err != nil {
// 		return err.Error()
// 	}

// 	about := GetIDAbout(mconn, collectionname, dataabout)
// 	if about != (About{}) {
// 		return GCFReturnStruct(CreateResponse(true, "Success: Get ID About", dataabout))
// 	} else {
// 		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID About", dataabout))
// 	}
// }

// <--- ini gallery --->

// gallery post
func GCFCreateGalleryy(publickey, MONGOCONNSTRINGENV, dbname, colluser, collgallery string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datagallery Gallery
				err := json.NewDecoder(r.Body).Decode(&datagallery)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				} else {
					CreateGallery(mconn, collgallery, Gallery{
						ID:          datagallery.ID,
						Title:       datagallery.Title,
						Description: datagallery.Description,
						Image:       datagallery.Image,
						Status:      datagallery.Status,
					})
					response.Status = true
					response.Message = "Gallery creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete gallery
func GCFDeleteGalleryy(publickey, MONGOCONNSTRINGENV, dbname, colluser, collgallery string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token

		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken

		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)

			if auth2.Role == "admin" {
				var datagallery Gallery
				err := json.NewDecoder(r.Body).Decode(&datagallery)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteGallery(mconn, collgallery, datagallery)
					response.Status = true
					response.Message = "Gallery Delete successful"
					CreateResponse(true, "Success Delete Gallery", datagallery)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// // update gallery
func GCFUpdateGalleryy(publickey, MONGOCONNSTRINGENV, dbname, colluser, collgallery string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User
	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		}
		auth2 := FindUser(mconn, colluser, authdata)
		if auth2.Role == "admin" {
			var datagallery Gallery
			err := json.NewDecoder(r.Body).Decode(&datagallery)
			if err != nil {
				response.Message = "Error parsing application/json: " + err.Error()
			} else {
				UpdatedGallery(mconn, collgallery, bson.M{"id": datagallery.ID}, datagallery)
				response.Status = true
				response.Message = "Gallery Updated Succescfull"
				CreateResponse(true, "Success Update Gallery", datagallery)
			}
		} else {
			response.Message = "ANDA BUKAN ADMIN"
		}
	}
	return GCFReturnStruct(response)
}

// get all gallery
func GCFGetAllGalleryy(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datagallery := GetAllGallery(mconn, collectionname)
	if datagallery != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Gallery", datagallery))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Gallery", datagallery))
	}
}

// get all gallery by id
func GCFGetAllGalleryyID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datagallery Gallery
	err := json.NewDecoder(r.Body).Decode(&datagallery)
	if err != nil {
		return err.Error()
	}

	gallery := GetIDGallery(mconn, collectionname, datagallery)
	if gallery != (Gallery{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Gallery", datagallery))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Gallery", datagallery))
	}
}

// <--- ini contact --->

// contact post
func GCFCreateContactt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontact string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontact Contack
				err := json.NewDecoder(r.Body).Decode(&datacontact)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateContact(mconn, collcontact, Contack{
						ID:      datacontact.ID,
						Subject: datacontact.Subject,
						Message: datacontact.Message,
						Email:   datacontact.Email,
						Phone:   datacontact.Phone,
						Status:  datacontact.Status,
					})
					response.Status = true
					response.Message = "Contact creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete contact
func GCFDeleteContactt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontact string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontact Contack
				err := json.NewDecoder(r.Body).Decode(&datacontact)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteContact(mconn, colluser, datacontact)
					response.Status = true
					response.Message = "Product Delete successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// update contact
func GCFUpdateContactt(publickey, MONGOCONNSTRINGENV, dbname, colluser, collcontact string, r *http.Request) string {
	var respon Credential
	respon.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		respon.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			respon.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var datacontact Contack
				err := json.NewDecoder(r.Body).Decode(&datacontact)
				if err != nil {
					respon.Message = "Error parsing application/json: " + err.Error()
				} else {
					UpdatedContact(mconn, colluser, bson.M{"id": datacontact.ID}, datacontact)
					respon.Status = true
					respon.Message = "About Product Succescfull"
					GCFReturnStruct(CreateResponse(true, "Success Update Product", datacontact))
				}
			} else {
				respon.Message = "ANDA BUKAN ADMIN"
			}

		}
	}
	return GCFReturnStruct(respon)
}

// get all contact
func GCFGetAllContactt(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacontact := GetAllContact(mconn, collectionname)
	if datacontact != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Contact", datacontact))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Contact", datacontact))
	}
}

// get all contact by id
func GCFGetAllContacttID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datacontact Contack
	err := json.NewDecoder(r.Body).Decode(&datacontact)
	if err != nil {
		return err.Error()
	}

	contact := GetIdContact(mconn, collectionname, datacontact)
	if contact != (Contack{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Contact", datacontact))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Contact", datacontact))
	}
}

// <--- ini iklan --->

// iklan post
func GCFCreateIklann(publickey, MONGOCONNSTRINGENV, dbname, colluser, collectioniklan string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User
	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"

		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataiklan Iklan
				err := json.NewDecoder(r.Body).Decode(&dataiklan)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					CreateIklan(mconn, collectioniklan, Iklan{
						ID:          dataiklan.ID,
						Title:       dataiklan.Title,
						Description: dataiklan.Description,
						Image:       dataiklan.Image,
						Status:      dataiklan.Status,
					})
					response.Status = true
					response.Message = "Iklan creation successful"
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// // delete iklan
func GCFDeleteIklann(publickey, MONGOCONNSTRINGENV, dbname, colluser, collectioniklan string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User
	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataiklan Iklan
				err := json.NewDecoder(r.Body).Decode(&dataiklan)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteIklan(mconn, collectioniklan, dataiklan)
					response.Status = true
					response.Message = "Iklan Delete successful"
					CreateResponse(true, "Success Delete Iklan", dataiklan)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// // update iklan
func GCFUpdateIklann(publickey, MONGOCONNSTRINGENV, dbname, colluser, collectioniklan string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var authdata User
	gettoken := r.Header.Get("token")

	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		authdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			auth2 := FindUser(mconn, colluser, authdata)
			if auth2.Role == "admin" {
				var dataiklan Iklan
				err := json.NewDecoder(r.Body).Decode(&dataiklan)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					UpdatedIklan(mconn, collectioniklan, bson.M{"id": dataiklan.ID}, dataiklan)
					response.Status = true
					response.Message = "Iklan Updated Succescfull"
					CreateResponse(true, "Success Update Iklan", dataiklan)
				}
			} else {
				response.Message = "ANDA BUKAN ADMIN"
			}
		}
	}
	return GCFReturnStruct(response)
}

// get all iklan
func GCFGetAllIklann(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataiklan := GetAllIklan(mconn, collectionname)
	if dataiklan != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Iklan", dataiklan))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Iklan", dataiklan))
	}
}

// get all iklan by id
func GCFGetAllIklannID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataiklan Iklan
	err := json.NewDecoder(r.Body).Decode(&dataiklan)
	if err != nil {
		return err.Error()
	}

	iklan := GetIDIklan(mconn, collectionname, dataiklan)
	if iklan != (Iklan{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Iklan", dataiklan))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Iklan", dataiklan))
	}
}

func GCFDeleteLineString(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return err.Error()
	}

	if err := DeleteLinestring(mconn, collectionname, dataline); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Delete LineString", dataline))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Delete LineString", dataline))
	}
}

func GCFUpdateLinestring(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname) // Assuming SetConnection is defined somewhere

	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Failed to decode request body", nil))
	}

	if r.Header.Get("Secret") == os.Getenv("SECRET") {
		if err := UpdatedLinestring(mconn, collectionname, bson.M{"properties.coordinates": dataline.Geometry.Coordinates}, dataline); err == nil {
			return GCFReturnStruct(CreateResponse(true, "Success: LineString updated", dataline))
		} else {
			return GCFReturnStruct(CreateResponse(false, "Failed to update LineString", nil))
		}
	} else {
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}
}

func GCFCreateIklannN(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataiklan Iklan
	err := json.NewDecoder(r.Body).Decode(&dataiklan)
	if err != nil {
		return err.Error()
	}

	if err := CreateIklan(mconn, collectionname, dataiklan); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Create Iklan", dataiklan))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Iklan", dataiklan))
	}
}

func GCFCreateLineStringgg(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return err.Error()
	}

	if r.Header.Get("Secret") == os.Getenv("SECRET") {
		// Handling Authorization
		if err != PostLinestring(mconn, collectionname, dataline) {
			return GCFReturnStruct(CreateResponse(true, "Success: LineString created", dataline))
		} else {
			return GCFReturnStruct(CreateResponse(false, "Failed to create LineString", nil))
		}

	} else {
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// This part is unreachable, so you might want to remove it
	// return GCFReturnStruct(CreateResponse(false, "Success to create LineString", nil))
}

func GCFCreatePolygone(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var datapolygone GeoJsonPolygon
	err := json.NewDecoder(r.Body).Decode(&datapolygone)
	if err != nil {
		return err.Error()
	}

	// Handling Authorization
	if err := PostPolygone(mconn, collectionname, datapolygone); err != nil {
		// Success
		return GCFReturnStruct(CreateResponse(true, "Success Create Polygone", datapolygone))
	} else {
		// Failure
		return GCFReturnStruct(CreateResponse(false, "Failed Create Polygone", datapolygone))
	}
}

func GCFPoint(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datapoint GeometryPoint

	// Decode the request body
	if err := json.NewDecoder(r.Body).Decode(&datapoint); err != nil {
		log.Printf("Error decoding request body: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Check for the "Secret" header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Attempt to post the data point to MongoDB
	if err := PostPoint(mconn, collectionname, datapoint); err != nil {
		log.Printf("Error posting data point to MongoDB: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Failed to create point", nil))
	}

	log.Println("Success: Point created")
	return GCFReturnStruct(CreateResponse(true, "Success: Point created", datapoint))
}

func GCFlineStingCreate(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}
	PostLinestring(mconn, collection, geojsonline)
	return GCFReturnStruct(geojsonline)
}

func GCFlineStingCreatea(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Checking Secret Header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Handling Authorization
	PostLinestring(mconn, collection, geojsonline)

	return GCFReturnStruct(CreateResponse(true, "Success: LineString created", geojsonline))
}

func GCFCreatePolygonee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var datapolygone GeoJsonPolygon
	err := json.NewDecoder(r.Body).Decode(&datapolygone)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Checking Secret Header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Handling Authorization
	if err := PostPolygone(mconn, collectionname, datapolygone); err != nil {
		log.Printf("Error creating polygon: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Failed Create Polygone", nil))
	}

	log.Println("Success: Polygon created")
	return GCFReturnStruct(CreateResponse(true, "Success Create Polygone", datapolygone))
}

func GCFCreatePostLocation(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var datapostlocation Location
	err := json.NewDecoder(r.Body).Decode(&datapostlocation)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Checking Secret Header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Handling Authorization
	if err := PostLocation(mconn, collectionname, datapostlocation); err != nil {
		log.Printf("Error creating polygon: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Failed Create Post Location", nil))
	}

	log.Println("Success: Polygon created")
	return GCFReturnStruct(CreateResponse(true, "Success Create Post Location", datapostlocation))
}

func Registrasi(token, mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if usernameExists(mongoenv, dbname, datauser) {
		response.Message = "Username telah dipakai"
	} else {
		if err != nil {
			response.Message = "error parsing application/json: " + err.Error()
		} else {
			hash, hashErr := HashPassword(datauser.Password)
			if hashErr != nil {
				response.Message = "Gagal Hash Password" + err.Error()
			}
			InsertUserdata(mconn, collname, datauser.Username, hash, datauser.No_whatsapp)
			response.Message = "Berhasil Input data"

			var username = datauser.Username
			var password = datauser.Password
			var nohp = datauser.No_whatsapp

			dt := &wa.TextMessage{
				To:       nohp,
				IsGroup:  false,
				Messages: "Selamat anda berhasil registrasi, berikut adalah username anda: " + username + " dan ini adalah password anda: " + password + "\nDisimpan baik baik ya",
			}

			atapi.PostStructWithToken[atmessage.Response]("Token", os.Getenv(token), dt, "https://api.wa.my.id/api/send/message/text")
		}
	}
	return GCFReturnStruct(response)
}

func GCFCreateTesting(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datatesting Testing
	err := json.NewDecoder(r.Body).Decode(&datatesting)
	if err != nil {
		return err.Error()
	}

	if err := PostTesting(mconn, collectionname, datatesting); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Create Testing", datatesting))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Testing", datatesting))
	}
}

func GCFGetallTesting(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datatesting := GetAllTesting(mconn, collectionname)
	if datatesting != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Testing", datatesting))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Testing", datatesting))
	}
}

func GCFDeleteTesting(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datatesting Testing
	err := json.NewDecoder(r.Body).Decode(&datatesting)
	if err != nil {
		return err.Error()
	}

	if err := DeleteTesting(mconn, collectionname, datatesting); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Delete Testing", datatesting))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Delete Testing", datatesting))
	}
}

func GCFUpdatedTesting(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datatesting Testing
	err := json.NewDecoder(r.Body).Decode(&datatesting)
	if err != nil {
		return err.Error()
	}

	if err := UpdatedTesting(mconn, collectionname, bson.M{"id": datatesting.ID}, datatesting); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Update Testing", datatesting))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Update Testing", datatesting))
	}
}
