package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	MQTT "github.com/eclipse/paho.mqtt.golang"
)

type Config struct {
	DefenseHost      string
	DefenseHTTPSPort int
	DefenseUsername  string
	DefensePassword  string
}

type RSAx struct {
	privateKey *rsa.PrivateKey
}

func (r *RSAx) GenerateKeyPair(bits int) error {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	r.privateKey = key
	return nil
}

func (r *RSAx) GetPublicKey() *rsa.PublicKey {
	if r.privateKey == nil {
		return nil
	}
	return &r.privateKey.PublicKey
}

func (r *RSAx) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, errors.New("missing private key")
	}

	// tenta base64 decode (como no seu código)
	decoded, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err == nil {
		ciphertext = decoded
	}

	return rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, ciphertext)
}

type Defense struct {
	Host string
	Port string
}

func NewDefense(host, port string) *Defense {
	return &Defense{Host: host, Port: port}
}

type api struct {
	Host    string
	Port    string
	Token   string
	headers map[string]string
}

func (d *api) createHeaders(token string) {
	h := make(map[string]string)
	h["Content-Type"] = "application/json"
	if token != "" {
		h["X-Subject-Token"] = token
	}
	d.headers = h
}

func (d *api) createURL(host, port, path string) string {
	return "https://" + host + ":" + port + path
}

func (d *api) req(method, path string, data any) (int, []byte, error) {
	url := d.createURL(d.Host, d.Port, path)
	d.createHeaders(d.Token)

	req, err := http.NewRequest(method, url, toBuffer(data))
	if err != nil {
		return 0, nil, err
	}

	for k, v := range d.headers {
		req.Header.Add(k, v)
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()

	resData, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, err
	}

	return res.StatusCode, resData, nil
}

func (d *api) Post(path string, data any) (uint, []byte, error) {
	code, resData, err := d.req(http.MethodPost, path, data)
	if err != nil {
		return 0, resData, errors.New("error on POST request\n" + err.Error())
	}
	return uint(code), resData, nil
}

type EncDataPayload struct {
	UserName   string `json:"userName"`
	ClientType string `json:"clientType"`
}

type EncDataRes struct {
	Realm       string `json:"realm"`
	RandomKey   string `json:"randomKey"`
	EncryptType string `json:"encryptType"`
	Publickey   string `json:"publickey"`
}

type EncData struct {
	Payload EncDataPayload
	Res     EncDataRes
}

func (e *EncData) CreatePayload(username string) {
	e.Payload = EncDataPayload{
		UserName:   "system",
		ClientType: "WINPC_V2",
	}
}

func (e *EncData) SetRes(data []byte) {
	var res EncDataRes
	if err := json.Unmarshal(data, &res); err != nil {
		return
	}
	e.Res = res
}

type AuthPayload struct {
	Signature   string `json:"signature"`
	UserName    string `json:"userName"`
	RandomKey   string `json:"randomKey"`
	PublicKey   string `json:"publicKey"`
	EncryptType string `json:"encryptType"`
	IpAddress   string `json:"ipAddress"`
	ClientType  string `json:"clientType"`
	UserType    string `json:"userType"`
}

type AuthRes struct {
	Token        string `json:"token"`
	SecretKey    string `json:"secretKey"`
	SecretVector string `json:"secretVector"`
	Code         int    `json:"code"`
}

type Auth struct {
	Payload   AuthPayload
	Res       AuthRes
	Signature string
}

func (a *Auth) CreatePayload(signature, userName, randomKey, publicKey string) {
	a.Payload = AuthPayload{
		Signature:   signature,
		UserName:    userName,
		RandomKey:   randomKey,
		PublicKey:   publicKey,
		EncryptType: "MD5",
		IpAddress:   "",
		ClientType:  "WINPC_V2",
		UserType:    "0",
	}
}

func (a *Auth) hash(data string) string {
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

func (a *Auth) CreateSignature(username, password, realm, randomKey string) {
	hash := a.hash(password)
	hash = a.hash(username + hash)
	hash = a.hash(hash)
	hash = a.hash(username + ":" + realm + ":" + hash)
	hash = a.hash(hash + ":" + randomKey)
	a.Signature = hash
}

func (a *Auth) SetRes(data []byte) error {
	if err := json.Unmarshal(data, &a.Res); err != nil {
		return errors.New("error on unmarshall auth response\n" + err.Error())
	}
	return nil
}

func (d *Defense) Auth(username, password, rsaPK string) (AuthRes, error) {
	const authEndpoint = "/brms/api/v1.0/accounts/authorize"

	encData := &EncData{}
	auth := &Auth{}

	defenseAPI := api{
		Host: d.Host,
		Port: d.Port,
	}

	// etapa 1: encData
	encData.CreatePayload(username)

	_, encDataRes, err := defenseAPI.Post(authEndpoint, encData.Payload)
	if err != nil {
		return auth.Res, errors.New("error on get encrypted data\n" + err.Error())
	}

	encData.SetRes(encDataRes)

	// envia publicKey limpa (se fornecida)
	if rsaPK != "" {
		encData.Res.Publickey = rsaPK
	}

	// etapa 2: auth
	auth.CreateSignature(username, password, encData.Res.Realm, encData.Res.RandomKey)
	auth.CreatePayload(auth.Signature, username, encData.Res.RandomKey, encData.Res.Publickey)

	_, authRes, err := defenseAPI.Post(authEndpoint, auth.Payload)
	if err != nil {
		return auth.Res, errors.New("error on authenticate\n" + err.Error())
	}

	if err := auth.SetRes(authRes); err != nil {
		return auth.Res, err
	}

	if auth.Res.Token == "" {
		return auth.Res, errors.New("token not created")
	}

	return auth.Res, nil
}

func toBuffer(data any) *bytes.Buffer {
	b, _ := json.Marshal(data)
	return bytes.NewBuffer(b)
}

func buildPublicKeyClean(pub *rsa.PublicKey) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyDER}
	publicKeyPEMString := string(pem.EncodeToMemory(&publicKeyPEM))

	var clean string
	for _, line := range strings.Split(publicKeyPEMString, "\n") {
		if !strings.Contains(line, "PUBLIC KEY") && line != "" {
			clean += line
		}
	}
	return clean, nil
}

func GetDefenseKeysAndToken(cfg Config) (secretKey, secretVector, token string, err error) {
	r := &RSAx{}
	if err := r.GenerateKeyPair(2048); err != nil {
		return "", "", "", fmt.Errorf("error generating RSA key pair: %w", err)
	}

	pubClean, err := buildPublicKeyClean(r.GetPublicKey())
	if err != nil {
		return "", "", "", err
	}

	d := NewDefense(cfg.DefenseHost, fmt.Sprintf("%d", cfg.DefenseHTTPSPort))
	res, err := d.Auth(cfg.DefenseUsername, cfg.DefensePassword, pubClean)
	if err != nil {
		return "", "", "", fmt.Errorf("error on defense auth: %w", err)
	}

	sv, err := r.Decrypt([]byte(res.SecretVector))
	if err != nil {
		return "", "", "", fmt.Errorf("error decrypting secret vector: %w", err)
	}
	sk, err := r.Decrypt([]byte(res.SecretKey))
	if err != nil {
		return "", "", "", fmt.Errorf("error decrypting secret key: %w", err)
	}

	return string(sk), string(sv), res.Token, nil
}

type MqConfigRes struct {
	Code int    `json:"code"`
	Desc string `json:"desc"`
	Data struct {
		EnableTls string `json:"enableTls"`
		Password  string `json:"password"` // HEX
		Mqtt      string `json:"mqtt"`     // host:port
		Addr      string `json:"addr"`
		UserName  string `json:"userName"`
	} `json:"data"`
}

func GetMqConfig(cfg Config, token string) (MqConfigRes, error) {
	const mqEndpoint = "/brms/api/v1.0/BRM/Config/GetMqConfig"

	defenseAPI := api{
		Host:  cfg.DefenseHost,
		Port:  fmt.Sprintf("%d", cfg.DefenseHTTPSPort),
		Token: token,
	}

	_, res, err := defenseAPI.Post(mqEndpoint, map[string]any{})
	if err != nil {
		return MqConfigRes{}, fmt.Errorf("error calling GetMqConfig: %w", err)
	}

	var out MqConfigRes
	if err := json.Unmarshal(res, &out); err != nil {
		return MqConfigRes{}, fmt.Errorf("error unmarshalling GetMqConfig response: %w", err)
	}

	if out.Code != 1000 {
		return out, fmt.Errorf("GetMqConfig returned code=%d desc=%s", out.Code, out.Desc)
	}
	if out.Data.Password == "" || out.Data.UserName == "" || out.Data.Mqtt == "" {
		return out, fmt.Errorf("GetMqConfig returned missing fields (password/userName/mqtt)")
	}

	return out, nil
}

func DecryptPassword(passwordHex string, sk, sv string) (string, error) {
	passwordBytes, err := hex.DecodeString(passwordHex)
	if err != nil {
		return "", err
	}
	passwordBase64 := base64.StdEncoding.EncodeToString(passwordBytes)
	decrypted, err := GetAESDecrypted(passwordBase64, sk, sv)
	if err != nil {
		return "", err
	}
	return decrypted, nil
}

func GetAESDecrypted(encryptedBase64, key, iv string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)

	ciphertext = PKCS5UnPadding(ciphertext)
	return string(ciphertext), nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	unpadding := int(src[length-1])
	if unpadding <= 0 || unpadding > aes.BlockSize || unpadding > length {
		return src
	}
	return src[:(length - unpadding)]
}

func fallbackString(flagValue, envVar string) string {
	if flagValue != "" {
		return flagValue
	}
	if v, ok := os.LookupEnv(envVar); ok {
		return v
	}
	return ""
}

func fallbackInt(flagValue int, envVar string) int {
	if flagValue != 0 {
		return flagValue
	}
	if v, ok := os.LookupEnv(envVar); ok {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return 0
}

// ============ MQTT (Go) ============
var currentDefTopic string
var currentDefPayload string

type payloadDefense struct {
	Method string `json:"method"`
	Info   []struct {
		DeviceCode        string   `json:"deviceCode"`
		ChannelSeq        int      `json:"channelSeq"`
		UnitType          int      `json:"unitType"`
		UnitSeq           int      `json:"unitSeq"`
		NodeType          string   `json:"nodeType"`
		NodeCode          string   `json:"nodeCode"`
		AlarmCode         string   `json:"alarmCode"`
		AlarmStat         string   `json:"alarmStat"`
		AlarmType         string   `json:"alarmType"`
		AlarmGrade        string   `json:"alarmGrade"`
		AlarmPicture      string   `json:"alarmPicture"`
		AlarmDate         string   `json:"alarmDate"`
		Memo              string   `json:"memo"`
		ExtData           string   `json:"extData"`
		LinkVideoChannels []any    `json:"linkVideoChannels"`
		UserIds           []any    `json:"userIds"`
		AlarmSourceName   string   `json:"alarmSourceName"`
		RuleThreshold     int      `json:"ruleThreshold"`
		StayNumber        int      `json:"stayNumber"`
		PlanTemplateID    string   `json:"planTemplateId"`
		DeviceName        string   `json:"deviceName"`
		LinkedOutput      string   `json:"linkedOutput"`
		MapIds            []string `json:"mapIds"`
	} `json:"info"`
}

func messageHandler(_ MQTT.Client, msg MQTT.Message) {
	currentDefPayload = string(msg.Payload())
	fmt.Printf("Tamanho: %d\n", len(currentDefPayload))
	fmt.Printf("Tamanho event: %d\n", len(msg.Payload()))
	fmt.Printf("Current payload: %s\n", currentDefPayload)
	fmt.Printf("Topic: %s\n", msg.Topic())

	var evento payloadDefense
	if err := json.Unmarshal(msg.Payload(), &evento); err != nil {
		fmt.Printf("Error decoding JSON: %v\n", err)
		return
	}
	// if len(evento.Info) > 0 {
	// 	fmt.Printf("Alarm type: %s | Device name: %s\n", evento.Info[0].AlarmType, evento.Info[0].DeviceName)
	// }
}

func main() {
	var (
		host = flag.String("host", "10.100.61.138", "Defense host")
		port = flag.Int("port", 443, "Defense HTTPS port")
		user = flag.String("user", "system", "Defense username")
		pass = flag.String("pass", "", "Defense password")

		topic    = flag.String("topic", "mq/event/msg/topic/#", "MQTT topic to subscribe")
		clientID = flag.String("clientid", "mqtt-client-idDADAsa", "MQTT client id")
	)
	flag.Parse()

	cfg := Config{
		DefenseHost:      fallbackString(*host, "DEFENSE_HOST"),
		DefenseHTTPSPort: fallbackInt(*port, "DEFENSE_PORT"),
		DefenseUsername:  fallbackString(*user, "DEFENSE_USER"),
		DefensePassword:  fallbackString(*pass, "DEFENSE_PASSWORD"),
	}
	if cfg.DefenseHost == "" || cfg.DefenseHTTPSPort == 0 || cfg.DefenseUsername == "" || cfg.DefensePassword == "" {
		log.Fatal("missing required params: --host --port --user --pass (or DEFENSE_HOST/DEFENSE_PORT/DEFENSE_USER/DEFENSE_PASSWORD)")
	}

	// 1) token + secretKey/secretVector (descriptografados)
	secretKey, secretVector, token, err := GetDefenseKeysAndToken(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// 2) GetMqConfig com token
	mqCfg, err := GetMqConfig(cfg, token)
	if err != nil {
		log.Fatal(err)
	}

	// 3) descriptografa senha mqtt (data.password HEX)
	mqttPass, err := DecryptPassword(mqCfg.Data.Password, secretKey, secretVector)
	if err != nil {
		log.Fatal(err)
	}

	// 4) conecta no broker mqtt e assina tópico
	parts := strings.Split(mqCfg.Data.Mqtt, ":")
	if len(parts) != 2 {
		log.Fatalf("invalid mqCfg.data.mqtt value: %s", mqCfg.Data.Mqtt)
	}
	mqttHost := parts[0]
	mqttPort := parts[1]

	useTLS := mqCfg.Data.EnableTls == "1"
	var brokerURL string
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	if useTLS {
		brokerURL = "ssl://" + mqttHost + ":" + mqttPort
	} else {
		brokerURL = "tcp://" + mqttHost + ":" + mqttPort
	}

	opts := MQTT.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(*clientID).
		SetUsername(mqCfg.Data.UserName).
		SetPassword(mqttPass)

	if useTLS {
		opts.SetTLSConfig(tlsCfg)
	}

	client := MQTT.NewClient(opts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatalf("Error connecting to MQTT broker: %v\n", token.Error())
	}

	fmt.Printf("Connected MQTT: %s (tls=%v) user=%s\n", brokerURL, useTLS, mqCfg.Data.UserName)
	fmt.Printf("Subscribing to topic: %s\n", *topic)

	if token := client.Subscribe(*topic, 0, messageHandler); token.Wait() && token.Error() != nil {
		log.Fatalf("Error subscribing to topic: %v\n", token.Error())
	}
	currentDefTopic = *topic
	fmt.Printf("Subscribed to topic: %s\n", *topic)

	// Wait for Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	fmt.Println("\nDisconnecting...")
	client.Disconnect(250)
}
