package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func main() {
	const method = "POST"
	const contextPath = "/sessions"
	const host = "rolesanywhere.cn-northwest-1.amazonaws.com.cn"
	const signedHeaders = "content-type;host;x-amz-date;x-amz-x509"

	account := flag.String("account", "", "AWS Account ID")
	region := flag.String("region", "", "AWS Region")
	location := flag.String("location", "", "AWS Location (aws|aws-cn)")
	keyPath := flag.String("keyPath", "", "Private Key")
	certPath := flag.String("certPath", "", "Certificate")
	roleName := flag.String("roleName", "", "Role Name")
	trustId := flag.String("trustId", "", "AWS Trust ARN Number")
	profileId := flag.String("profileId", "", "AWS Profile ARN Number")
	bucketName := flag.String("bucketName", "", "AWS S3 Bucket Name")
	uploadFiles := flag.String("uploadFiles", "", "Upload Files Location, Split By ',' ")
	s3FolderName := flag.String("s3FolderName", "", "S3 Folder Name, End Of '/'")

	flag.Parse()

	checkNotEmpty("account", *account)
	checkNotEmpty("region", *region)
	checkNotEmpty("location", *location)
	checkNotEmpty("key", *keyPath)
	checkNotEmpty("cert", *certPath)
	checkNotEmpty("role", *roleName)
	checkNotEmpty("trust", *trustId)
	checkNotEmpty("profile", *profileId)
	checkNotEmpty("bucket", *bucketName)
	checkNotEmpty("uploadFiles", *uploadFiles)
	checkNotEmpty("s3folder", *s3FolderName)

	if *location != "aws" && *location != "aws-cn" {
		fmt.Println("请指定一个有效的位置：--location aws 或 --location aws-cn")
		os.Exit(1)
	}

	var roleArn string = "arn:" + *location + ":iam::" + *account + ":role/" + *roleName
	var trustArn string = "arn:" + *location + ":rolesanywhere:" + *region + ":" + *account + ":trust-anchor/" + *trustId
	var profileArn string = "arn:" + *location + ":rolesanywhere:" + *region + ":" + *account + ":profile/" + *profileId

	//获取当前时间
	now := time.Now().UTC()
	formatTime := now.Format("20060102T150405Z")
	//formatTime := "20240607T013143Z"
	var sope string = formatTime[:8]

	var crtAlgorithm string

	algorithm, number, x509Header := getCertinfo(*certPath)

	switch algorithm {
	case "RSA":
		crtAlgorithm = "AWS4-X509-RSA-SHA256"
	case "ECDSA":
		crtAlgorithm = "AWS4-X509-ECDSA-SHA256"
	}
	var canonicalHeaders string = "content-type:application/x-amz-json-1.0\n" +
		"host:" + host + "\n" +
		"x-amz-date:" + formatTime + "\n" +
		"x-amz-x509:" + x509Header + "\n"

	var requestBody string = "{\"durationSeconds\": 3600, " +
		"\"profileArn\": \"" + profileArn + "\", " +
		"\"roleArn\": \"" + roleArn + "\", " +
		"\"trustAnchorArn\": \"" + trustArn + "\"" +
		"}"
	hashBody := strings.ToLower(getHash(requestBody))
	var canonicalRequest string = method + "\n" +
		contextPath + "\n" + "\n" +
		canonicalHeaders + "\n" +
		signedHeaders + "\n" + hashBody
	var StringToSign string = crtAlgorithm + "\n" +
		formatTime + "\n" +
		sope + "/" + *region + "/rolesanywhere/aws4_request" + "\n" +
		getHash(canonicalRequest)
	privateKey, _ := getPrivateKey(*keyPath, algorithm)
	signature, _ := calculateSignature(privateKey, StringToSign)
	var credential string = number + "/" + sope + "/" + *region + "/rolesanywhere/aws4_request"
	var authorization = crtAlgorithm + " Credential=" + credential + ", SignedHeaders=" + signedHeaders +
		", Signature=" + signature

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}
	url := fmt.Sprintf("https://%s%s", host, contextPath)
	request, err := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewBufferString(requestBody))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.0")
	request.Header.Set("Accept-Encoding", "gzip, deflate, br")
	request.Header.Set("X-Amz-Date", formatTime)
	request.Header.Set("X-Amz-X509", x509Header)
	request.Header.Set("Authorization", authorization)
	resp, err := client.Do(request)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	responseBody := string(body)
	accessKey, secretAccessKey, sessionToken, _ := getCredential(responseBody)
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretAccessKey, sessionToken)))
	s3client := s3.NewFromConfig(cfg)
	filePaths := strings.Split(*uploadFiles, ",")
	for _, filePath := range filePaths {
		s3FileLocaton := *s3FolderName + path.Base(filePath)
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("Couldn't open file %v to upload. Here's why: %v\n", filePath, err)
		} else {
			defer file.Close()
			_, err = s3client.PutObject(context.TODO(), &s3.PutObjectInput{
				Bucket: aws.String(*bucketName),
				Key:    aws.String(s3FileLocaton),
				Body:   file,
			})
			if err != nil {
				log.Printf("Couldn't upload file %v to %v:%v. Here's why: %v\n",
					filePath, bucketName, s3FileLocaton, err)
			}
		}
	}
}

// 定义结构体用于解析JSON
type AssumedRoleUser struct {
	Arn           string `json:"arn"`
	AssumedRoleId string `json:"assumedRoleId"`
}

type Credentials struct {
	AccessKeyId     string `json:"accessKeyId"`
	Expiration      string `json:"expiration"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
}

type CredentialSet struct {
	AssumedRoleUser  AssumedRoleUser `json:"assumedRoleUser"`
	Credentials      Credentials     `json:"credentials"`
	PackedPolicySize int             `json:"packedPolicySize"`
	RoleArn          string          `json:"roleArn"`
	SourceIdentity   string          `json:"sourceIdentity"`
}

type Response struct {
	CredentialSet []CredentialSet `json:"credentialSet"`
	SubjectArn    string          `json:"subjectArn"`
}

func checkNotEmpty(paramName, paramValue string) {
	if paramValue == "" {
		fmt.Printf("请提供必要的参数：--%s\n", paramName)
		os.Exit(1)
	}
}

func getCredential(body string) (key, secretKey, sessionT string, err error) {
	var response Response
	errs := json.Unmarshal([]byte(body), &response)
	if errs != nil {
		log.Fatal("解析JSON失败:", err)
		return
	}
	// 提取accessKeyId、secretAccessKey和sessionToken的值
	var accessKeyId, secretAccessKey, sessionToken string
	if len(response.CredentialSet) > 0 {
		accessKeyId = response.CredentialSet[0].Credentials.AccessKeyId
		secretAccessKey = response.CredentialSet[0].Credentials.SecretAccessKey
		sessionToken = response.CredentialSet[0].Credentials.SessionToken
	} else {
		fmt.Println("未找到凭证信息")
	}
	return accessKeyId, secretAccessKey, sessionToken, nil
}

func getCertinfo(certFilePath string) (algoriithm, serialNumber, base64String string) {
	certPEM, err := os.ReadFile(certFilePath)
	if err != nil {
		log.Fatal("加载crt证书错误")
		log.Fatal(err)
	}
	// 解析PEM格式的证书
	block, rest := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("failed to parse certificate PEM")
	}
	if len(rest) > 0 {
		log.Fatal("PEM data contains additional blocks")
	}
	//获取证书信息
	cert, err := x509.ParseCertificate(block.Bytes)
	publicKeyAlgorithm := cert.PublicKeyAlgorithm

	//获取serialNumber
	SerialNumber := cert.SerialNumber

	//获取base64编码后的
	certBase64 := base64.StdEncoding.EncodeToString(block.Bytes)
	return publicKeyAlgorithm.String(), SerialNumber.String(), certBase64
}

func getPrivateKey(keyFilePath, algorithm string) (crypto.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyFilePath)
	if err != nil {
		log.Fatal("加载key证书错误")
		log.Fatal(err)
	}
	// 解析PEM格式的证书
	block, rest := pem.Decode(keyPEM)
	if block == nil {
		log.Fatal("failed to parse certificate PEM")
	}
	if len(rest) > 0 {
		log.Fatal("PEM data contains additional blocks")
	}
	switch algorithm {
	case "RSA":
		return x509.ParsePKCS8PrivateKey(block.Bytes)

	case "ECDSA":
		return x509.ParseECPrivateKey(block.Bytes)

	default:
		return nil, errors.New("unsupported private key type")
	}
}

func getHash(body string) string {
	hashByte := sha256.Sum256([]byte(body))
	hashInt := new(big.Int).SetBytes(hashByte[:])
	// 将big.Int格式化为64位的十六进制字符串
	formattedHash := fmt.Sprintf("%064x", hashInt)
	return formattedHash

}

func calculateSignature(privateKey crypto.PrivateKey, stringToSign string) (string, error) {
	data := []byte(stringToSign)
	hash := sha256.Sum256(data)
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %v", err)
		}
		return hex.EncodeToString(signature), nil
	case *ecdsa.PrivateKey:
		signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %v", err)
		}
		return hex.EncodeToString(signature), nil
	default:
		return "", fmt.Errorf("unsupported private key type")
	}
}
