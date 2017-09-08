package ali_cdn_refresh

import (
	"sort"
	"bytes"
	"crypto/hmac"
	"hash"
	"crypto/sha1"
	"crypto/rand"
	"io"
	"encoding/base64"
	"net/url"
	"strings"
	"time"
	"crypto/md5"
	"encoding/hex"
	"log"
	"net/http"
	"errors"
	"io/ioutil"
)

const (
	AccessKeySecret = ""
	AccessKeyId = ""
)

// Additional function for function SignHeader.
func newHeaderSorter(m map[string]string) *headerSorter {
	hs := &headerSorter{
		Keys: make([]string, 0, len(m)),
		Vals: make([]string, 0, len(m)),
	}

	for k, v := range m {
		hs.Keys = append(hs.Keys, k)
		hs.Vals = append(hs.Vals, v)
	}
	return hs
}

// 用于signHeader的字典排序存放容器。
type headerSorter struct {
	Keys []string
	Vals []string
}

// Additional function for function SignHeader.
func (hs *headerSorter) Sort() {
	sort.Sort(hs)
}

// Additional function for function SignHeader.
func (hs *headerSorter) Len() int {
	return len(hs.Vals)
}

// Additional function for function SignHeader.
func (hs *headerSorter) Less(i, j int) bool {
	return bytes.Compare([]byte(hs.Keys[i]), []byte(hs.Keys[j])) < 0
}

// Additional function for function SignHeader.
func (hs *headerSorter) Swap(i, j int) {
	hs.Vals[i], hs.Vals[j] = hs.Vals[j], hs.Vals[i]
	hs.Keys[i], hs.Keys[j] = hs.Keys[j], hs.Keys[i]
}

func RefrechUrl(refreshUrl string) (err error) {
	HTTPMethod := "GET"
	//copy from alidoc https://help.aliyun.com/document_detail/27149.html?spm=5176.doc27200.6.608.CGJfd2
	params := map[string]string{}
	demostring := "SignatureVersion=1.0&Format=JSON&Timestamp=2015-08-06T02:19:46Z&AccessKeyId=testid&SignatureMethod=HMAC-SHA1&Version=2014-11-11&Action=DescribeCdnService&SignatureNonce=9b7a44b0-3be1-11e5-8c73-08002700c460"
	for _, kv := range strings.Split(demostring, "&") {
		pairs := strings.Split(kv, "=")
		params[pairs[0]] = pairs[1]
	}
	//Timestamp  AccessKeyId  SignatureNonce
	params["Timestamp"] = time.Now().UTC().Format(time.RFC3339)
	params["AccessKeyId"] = AccessKeyId
	params["SignatureNonce"] = getGuid()


	//refreshAction Action ObjectPath ObjectType=File
	params["Action"] = "RefreshObjectCaches"
	params["ObjectPath"] = refreshUrl
	params["ObjectType"] = "File"

	hs := newHeaderSorter(params)
	hs.Sort()

	// Get the CanonicalizedOSSHeaders
	CanonicalizedQueryString := ""
	for i := range hs.Keys {
		CanonicalizedQueryString += percentEncode(hs.Keys[i]) + "=" +
		percentEncode(hs.Vals[i]) + "&"
	}
	CanonicalizedQueryString = strings.TrimSuffix(CanonicalizedQueryString, "&")
	log.Println("CanonicalizedQueryString", CanonicalizedQueryString)

	stringToSign := HTTPMethod + "&" +
	percentEncode("/") + "&" +
	percentEncode(CanonicalizedQueryString)
	log.Println("stringToSign", stringToSign)

	h := hmac.New(func() hash.Hash {
		return sha1.New()
	}, []byte(AccessKeySecret+"&"))
	io.WriteString(h, stringToSign)
	signedStr := base64.StdEncoding.EncodeToString(h.Sum(nil))
	params["Signature"] = percentEncode(signedStr)

	queryStr := ""
	for k, v := range params {
		queryStr += k + "=" +
		v + "&"
	}

	queryStr = strings.TrimSuffix(queryStr, "&")

	reqUrl := "http://cdn.aliyuncs.com?" + queryStr
	log.Println(reqUrl)
	res, err := http.DefaultClient.Get(reqUrl)

	if err != nil {
		return err
	}
	bs, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	log.Println(string(bs))
	if res.StatusCode > 200 {
		return errors.New(res.Status)
	}

	return nil
}

func percentEncode(s string) string {
	s=url.QueryEscape(s)  //测试发现 go QueryEscape 够用了. 下面的转换Replace可选
	return s
	//return strings.Replace(
	//	strings.Replace(
	//		strings.Replace(s, "+", "%20", -1),
	//		"*", "%2A", -1),
	//	"%7E", "~", -1);
}
func getMd5String(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

//生成Guid字串
func getGuid() string {
	b := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return getMd5String(base64.URLEncoding.EncodeToString(b))
}