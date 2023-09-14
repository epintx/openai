package handler

import (
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"openai/internal/config"
	"openai/internal/service/fiter"
	"openai/internal/service/openai"
	"openai/internal/service/wechat"
	"openai/internal/wechataes"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	success  = []byte("success")
	warn     = "警告，检测到敏感词"
	requests sync.Map // K - 消息ID ， V - chan string
)

func WechatCheck(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	signature := query.Get("signature")
	timestamp := query.Get("timestamp")
	nonce := query.Get("nonce")
	echostr := query.Get("echostr")

	// 校验
	if wechat.CheckSignature(signature, timestamp, nonce, config.Wechat.Token) {
		w.Write([]byte(echostr))
		return
	}

	log.Println("此接口为公众号验证，不应该被手动调用，公众号接入校验失败")
}

type RequestMessage struct {
	XMLName      xml.Name `xml:"xml"`
	EncryptedMsg string   `xml:"Encrypt"`
}

// https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Passive_user_reply_message.html
// 微信服务器在五秒内收不到响应会断掉连接，并且重新发起请求，总共重试三次
func ReceiveMsg(w http.ResponseWriter, r *http.Request) {
	params := getRequestCheckParams(r)
	encryptedMsg, done := decodeWX(r, params)
	if done {
		return
	}

	msg := wechat.NewMsg(encryptedMsg)

	if msg == nil {
		echo(w, params, []byte("xml格式公众号消息接口，请勿手动调用"))
		return
	}

	log.Printf("ReceiveMsg user: %s %s", msg.FromUserName, msg.MsgType)

	// 非文本不回复(返回success表示不回复)
	switch msg.MsgType {
	// 未写的类型
	default:
		log.Printf("未实现的消息类型%s\n", msg.MsgType)
		echo(w, params, success)
	case "event":
		switch msg.Event {
		default:
			log.Printf("未实现的事件%s\n", msg.Event)
			echo(w, params, success)
		case "subscribe":
			log.Println("新增关注:", msg.FromUserName)
			b := msg.GenerateEchoData(config.Wechat.SubscribeMsg)
			echo(w, params, b)
			return
		case "unsubscribe":
			log.Println("取消关注:", msg.FromUserName)
			echo(w, params, success)
			return
		}
	// https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Receiving_standard_messages.html
	case "voice":
		msg.Content = msg.Recognition
	case "text":

	}

	// 敏感词检测
	if !fiter.Check(msg.Content) {
		warnWx := msg.GenerateEchoData(warn)
		echo(w, params, warnWx)
		return
	}

	var ch chan string
	v, ok := requests.Load(msg.MsgId)
	if !ok {
		ch = make(chan string)
		requests.Store(msg.MsgId, ch)
		ch <- openai.Query(msg.FromUserName, msg.Content, time.Second*time.Duration(config.Wechat.Timeout))
	} else {
		ch = v.(chan string)
	}

	select {
	case result := <-ch:
		if !fiter.Check(result) {
			result = warn
		}
		bs := msg.GenerateEchoData(result)
		echo(w, params, bs)
		requests.Delete(msg.MsgId)
	// 超时不要回答，会重试的
	case <-time.After(time.Second * 5):
	}
}

func Test(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	msg := query.Get("msg")
	respType := query.Get("type")
	if !fiter.Check(msg) {
		echoJson(w, "", warn)
		return
	}
	cg := testChatGpt(msg)
	gt := translateEnToZh(msg)

	v := map[string]string{
		"title":            msg,
		"chat_gpt":         cg,
		"google_translate": gt,
	}

	if respType == "json" {
		//json
		data, _ := json.Marshal(v)
		echoMsg(w, string(data), "")
	} else {

		filename := "/app/template.html"

		// 使用 os.Stat() 检查文件是否存在
		_, err := os.Stat(filename)
		if os.IsNotExist(err) {
			fmt.Printf("文件 %s 不存在\n", filename)
		} else if err == nil {
			fmt.Printf("文件 %s 存在\n", filename)
		} else {
			fmt.Println("发生错误：", err)
		}

		//html
		tmpl, err := template.ParseFiles(filename)
		// 创建一个缓冲区
		buffer := &strings.Builder{}
		err = tmpl.Execute(buffer, v)

		if err != nil {
			log.Fatal(err)
		}
		echoHtml(w, buffer.String(), "")
	}

}

func translateEnToZh(msg string) string {
	// 构建POST请求URL
	url := "https://translate.google.com/translate_a/single"

	// 构建POST请求体
	payload := strings.NewReader("client=gtx&sl=en&tl=zh-CN&dt=t&q=" + msg)

	// 发送POST请求
	response, err := http.Post(url, "application/x-www-form-urlencoded", payload)
	if err != nil {
		fmt.Println("请求失败:", err)
		return ""
	}
	defer response.Body.Close()

	// 读取响应内容
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("请求失败:", err)
		return ""
	}

	// 输出响应结果

	str := string(body)

	startIndex := strings.Index(str, "\"")
	if startIndex == -1 {
		fmt.Println("找不到双引号")
		return ""
	}

	endIndex := strings.Index(str[startIndex+1:], "\"") + startIndex + 1
	if endIndex == -1 {
		fmt.Println("找不到闭合的双引号")
		return ""
	}

	content := str[startIndex+1 : endIndex]
	return content
}

func testChatGpt(msg string) string {
	s := openai.Query("0", msg, time.Second*5)

	for i := 0; i < 5; i++ {

		suffix := "【回复“继续”以滚动查看】"
		if strings.Contains(s, suffix) {

			newr := openai.Query("0", "继续", time.Second*5)

			s = strings.Replace(s, suffix, newr, 1)

		}
	}
	return s
}

func echoJson(w http.ResponseWriter, replyMsg string, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var code int
	var message = replyMsg
	if errMsg != "" {
		code = -1
		message = errMsg
	}
	data, _ := json.Marshal(map[string]interface{}{
		"code":    code,
		"message": message,
	})
	w.Write(data)
}

func echoHtml(w http.ResponseWriter, replyMsg string, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	var message = replyMsg
	if errMsg != "" {
		message = errMsg
	}
	w.Write([]byte(message))
}

func echoMsg(w http.ResponseWriter, replyMsg string, errMsg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	var message = replyMsg
	if errMsg != "" {
		message = errMsg
	}
	w.Write([]byte(message))
}

func echo(w http.ResponseWriter, params openai.ParseCheckParam, data []byte) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	replyMsg := data // 替换为实际的回复消息

	ret, done := encodeWx(params, replyMsg)
	if done {
		return
	}
	w.Write(ret)

}

func decodeWX(r *http.Request, params openai.ParseCheckParam) ([]byte, bool) {

	// 读取请求体数据
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// 处理读取错误
		log.Printf("decodeWX 处理读取错误")
		return nil, true
	}

	// 解析XML数据
	format := "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>"
	var reqMsg RequestMessage
	_ = xml.Unmarshal(requestBody, &reqMsg)

	encryptedMsg := reqMsg.EncryptedMsg
	fromXML := fmt.Sprintf(format, encryptedMsg)

	cryptor, err := wechataes.NewWechatCryptor(config.Wechat.AppID, config.Wechat.Token, config.Wechat.AESKey)

	if err != nil {
		// 处理解密错误
		log.Printf("decodeWX NewWechatCryptor err %s", err)
		return nil, true
	}

	//log.Printf("params: %s", params)
	//log.Printf("fromXML:\n%s", fromXML)

	ret, err := cryptor.DecryptMsg(params.Signature, params.Timestamp, params.Nonce, fromXML)

	if err != nil {
		// 处理解密错误
		log.Printf("decodeWX DecryptMsg err %s", err)
		return nil, true
	}

	return []byte(ret), false
}

func getRequestCheckParams(r *http.Request) openai.ParseCheckParam {
	query := r.URL.Query()

	param := openai.ParseCheckParam{
		Signature: query.Get("signature"),
		Timestamp: query.Get("timestamp"),
		Nonce:     query.Get("nonce"),
		Echostr:   query.Get("echostr"),
	}
	return param
}

func encodeWx(params openai.ParseCheckParam, replyMsg []byte) ([]byte, bool) {
	// 使用AES加密回复消息

	cryptor, err := wechataes.NewWechatCryptor(config.Wechat.AppID, config.Wechat.Token, config.Wechat.AESKey)
	msg := string(replyMsg)
	//log.Printf("encodeWx source msg: \n%s", msg)
	timeC := time.Now().Unix()

	nonce, err := generateNonce(16)

	if err != nil {
		// generateNonce
		log.Printf("encodeWx generateNonce err %s", err)
		return nil, true
	}
	//log.Printf("encodeWx Nonce : %s", nonce)
	//log.Printf("encodeWx TimeStamp  %d", timeC)
	ret, err := cryptor.EncryptMsg(msg, strconv.FormatInt(timeC, 10), nonce)

	if err != nil {
		// 处理加密错误
		log.Printf("encodeWx EncryptMsg err %s", err)
		return nil, true
	}

	return []byte(ret), false
}

func generateNonce(length int) (string, error) {
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
