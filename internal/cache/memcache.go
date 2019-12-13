package cache

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"werther/internal/ldapclient"

	"github.com/hashicorp/go-memdb"
	"github.com/i-core/rlog"
	"github.com/labstack/gommon/log"
	"github.com/robfig/cron"
	"go.uber.org/zap"
)

var (
	// failCode means http request is failed.
	failCode = -1
	// succCode means http request is success.
	succCode = 0
	jobOnce  sync.Once
)

// MemCacheHandler cache ldap user info.
type MemCacheHandler struct {
	RWMutex    *sync.RWMutex
	Num        int
	LdapClient *ldapclient.Client
	Db         *memdb.MemDB
}

// User record ldap user info in cache.
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// APIResult return data to front.
type APIResult struct {
	Data     interface{} `json:"data"`      // result data.
	ErrNo    int         `json:"err_no"`    // err code.
	ErrMsg   string      `json:"err_msg"`   // error message.
	HTTPCode int         `json:"http_code"` // http code.
}

// Pagination return page info to front.
type Pagination struct {
	CurrentPage int `json:"current_page"`
	PageSize    int `json:"page_size"`
	Total       int `json:"total"`
}

// APIPageResult return data and page info to fron.
type APIPageResult struct {
	APIResult
	Pagination
}

// CacheLdapUsers cache ldap users's info.
func (mc *MemCacheHandler) CacheLdapUsers() error {
	entries, err := mc.LdapClient.SearchUserList([]string{"uid", "mail"})
	if err != nil {
		log.Error("Search ldap user failed ", zap.Error(err))
		return err
	}
	if mc.Num == len(entries) {
		log.Info("Cache info is already recently, user's num is ", mc.Num)
		return nil
	}
	// clear all old info.
	_, err = mc.clearAll()
	if err != nil {
		log.Error("Clear cache db error ", zap.Error(err))
		return err
	}

	// cache recent ldap user's info.
	users := []*User{}
	for _, v := range entries {
		uid, ok := v["uid"]
		if !ok {
			log.Warnf("Cache ldap account uid missing: %v", v)
			continue
		}
		email, ok := v["mail"]
		if !ok {
			log.Warnf("Cache ldap account email missing: %v", v)
			continue
		}
		user := User{Username: uid.(string), Email: email.(string)}
		users = append(users, &user)
	}
	// create a write transaction.
	txn := mc.Db.Txn(true)
	defer txn.Abort()
	for _, u := range users {
		if err := txn.Insert("user", u); err != nil {
			log.Error("Clear cache db error ", zap.Error(err))
			return err
		}
	}
	// commit the transaction.
	txn.Commit()
	mc.Num = len(users)
	log.Info("Cache ldap account success, user's num is ", len(users))
	return nil
}

// UpdateCronJob set cache db update cron job.
func (mc *MemCacheHandler) UpdateCronJob() error {
	var err error
	jobOnce.Do(func() {
		c := cron.New()
		// Task are scheduled and executed once every 15 minutes.
		err = c.AddFunc("0 */15 * * * ?", mc.cacheUpdate)
		if err != nil {
			log.Error("Add cache update cron job failed ", zap.Error(err))
			return
		}
		// start cron job.
		c.Start()
		log.Info("Cache cron job start success")
	})
	return err
}

func (mc *MemCacheHandler) cacheUpdate() {
	mc.CacheLdapUsers()
}

// clearAll clear all users's info in cache.
func (mc *MemCacheHandler) clearAll() (int, error) {
	// create a write transaction
	txn := mc.Db.Txn(true)
	defer txn.Abort()
	return txn.DeleteAll("user", "id")
}

// SearchUserByName search user in cache by username, support fuzzy query.
func (mc *MemCacheHandler) SearchUserByName(username string) ([]*User, error) {
	// create a read-only transaction
	txn := mc.Db.Txn(false)
	defer txn.Abort()
	// list all the user
	users := []*User{}
	it, err := txn.Get("user", "id")
	if err != nil {
		return nil, err
	}
	for obj := it.Next(); obj != nil; obj = it.Next() {
		u := obj.(*User)
		if strings.Contains(u.Username, username) {
			users = append(users, u)
		}
	}
	return users, nil
}

// SearchUsers return all user in cache.
func (mc *MemCacheHandler) SearchUsers() ([]*User, error) {
	// Create a read-only transaction
	txn := mc.Db.Txn(false)
	defer txn.Abort()
	// List all the user
	users := []*User{}
	it, err := txn.Get("user", "id")
	if err != nil {
		return nil, err
	}
	for obj := it.Next(); obj != nil; obj = it.Next() {
		u := obj.(*User)
		users = append(users, u)
	}
	return users, nil
}

// SearchUsersByPage get user by page, and return paging information to front.
func (mc *MemCacheHandler) SearchUsersByPage(current, pageSize int, username string) ([]*User, int, error) {
	if current <= 0 || pageSize <= 0 {
		return nil, 0, errors.New("param is invalid")
	}
	users, err := mc.SearchUserByName(username)
	if err != nil {
		return nil, 0, err
	}
	usersNum := len(users)
	startIndex := (current - 1) * pageSize
	endIndex := startIndex + pageSize
	if startIndex >= usersNum {
		return []*User{}, 0, nil
	}
	if endIndex > usersNum {
		endIndex = usersNum
	}
	return users[startIndex:endIndex], usersNum, nil
}

// NewMemCacheHandler creates a new instance of MemCacheHandler.
func NewMemCacheHandler(ldapClient *ldapclient.Client) *MemCacheHandler {
	log := rlog.FromContext(context.Background()).Sugar()
	if ldapClient == nil {
		log.Error("ldap client is nil")
		return nil
	}
	// create the DB schema
	schema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"user": &memdb.TableSchema{
				Name: "user",
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Username"},
					},
					"username": &memdb.IndexSchema{
						Name:    "username",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Username"},
					},
					"email": &memdb.IndexSchema{
						Name:    "email",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Email"},
					},
				},
			},
		},
	}
	// create a new data base.
	db, err := memdb.NewMemDB(schema)
	if err != nil {
		log.Error("init memory db error ", err)
		return nil
	}
	return &MemCacheHandler{
		RWMutex:    new(sync.RWMutex),
		LdapClient: ldapClient,
		Db:         db,
	}
}

// AddRoutes registers a route that serves static files.
func (mc *MemCacheHandler) AddRoutes(apply func(m, p string, h http.Handler, mws ...func(http.Handler) http.Handler)) {
	apply(http.MethodGet, "/users", mc.newListByPageHandler())
	apply(http.MethodGet, "/allusers", mc.newListALLHandler())
}

// newListByPageHandler return user info by pagination.
// currentPage means current page value, default is 1,
// pageSize means current page size value, default is 10.
func (mc *MemCacheHandler) newListByPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		queryStr := r.URL.Query().Get("q")
		pageInfo := Pagination{}
		if queryStr == "" || queryStr == "." {
			HTTPSuccPage(w, []*User{}, pageInfo)
			return
		}

		currentPage := r.URL.Query().Get("current_page")
		pageSize := r.URL.Query().Get("page_size")
		currentPageInt, err := strconv.Atoi(currentPage)
		if err != nil || currentPageInt <= 0 {
			currentPageInt = 1 // deafult current page is 1.
		}
		pageSizeInt, err := strconv.Atoi(pageSize)
		if err != nil || pageSizeInt <= 0 {
			pageSizeInt = 10 // default page size is 10.
		}
		users, total, err := mc.SearchUsersByPage(currentPageInt, pageSizeInt, queryStr)
		if err != nil {
			HTTPFail(w, err.Error())
			return
		}

		pageInfo.CurrentPage = currentPageInt
		pageInfo.PageSize = pageSizeInt
		pageInfo.Total = total
		HTTPSuccPage(w, users, pageInfo)
	}
}

func (mc *MemCacheHandler) newListALLHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := mc.SearchUsers()
		if err != nil {
			HTTPFail(w, err.Error())
			return
		}
		HTTPSuccess(w, users)
	}
}

func (mc *MemCacheHandler) newGetUserByNameHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if username == "" || username == "." {
			HTTPFail(w, "username is invalid")
			return
		}
		users, err := mc.SearchUserByName(username)
		if err != nil {
			HTTPFail(w, err.Error())
			return
		}
		HTTPSuccess(w, users)
	}
}

// HTTPSuccPage return data and page info to front.
func HTTPSuccPage(w http.ResponseWriter, data interface{}, pageInfo Pagination) {
	result := APIResult{}
	result.Data = data
	apiPageResult := APIPageResult{result, pageInfo}
	json.NewEncoder(w).Encode(apiPageResult)
}

// HTTPFailPage return data and page info to front.
func HTTPFailPage(w http.ResponseWriter, errMsg string) {
	apiPageResult := APIPageResult{}
	apiPageResult.ErrNo = failCode
	apiPageResult.ErrMsg = errMsg
	json.NewEncoder(w).Encode(apiPageResult)
}

// HTTPSuccess return data and success code to front.
func HTTPSuccess(w http.ResponseWriter, data interface{}) {
	result := APIResult{}
	result.Data = data
	result.ErrNo = succCode
	json.NewEncoder(w).Encode(result)
}

// HTTPFail return fail code to front.
func HTTPFail(w http.ResponseWriter, errMsg string) {
	result := APIResult{}
	result.Data = nil
	result.ErrNo = failCode
	result.ErrMsg = errMsg
	json.NewEncoder(w).Encode(result)
}
