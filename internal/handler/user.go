package handler

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"openai/internal/config"
	"openai/internal/service/fiter"
	"openai/internal/service/openai"
	"openai/internal/service/wechat"
	"openai/internal/wechataes"
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
	msg := r.URL.Query().Get("msg")
	if !fiter.Check(msg) {
		echoJson(w, "", warn)
		return
	}
	s := openai.Query("0", msg, time.Second*5)
	echoJson(w, s, "")
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

	log.Printf("params: %s", params)
	log.Printf("fromXML:\n%s", fromXML)

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
	log.Printf("encodeWx source msg: \n%s", msg)
	ret, err := cryptor.EncryptMsg(msg, params.Timestamp, params.Nonce)
	log.Printf("encodeWx ret msg: \n%s", ret)
	if err != nil {
		// 处理加密错误
		log.Printf("encodeWx EncryptMsg err %s", err)
		return nil, true
	}

	return []byte(ret), false
}
