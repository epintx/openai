### 03-03 国内被墙了，已支持设置代理，或者使用海外服务器
### 03-01 更新，替换ChatGPT接口了！速度超快的！
### 持续优化中，喜欢的同学给个🌟关注一下
### 声明：此项目请仅用于学习和体验技术，勿做商用

### 一、介绍
- 使用
  - 用作公众号被动回复。(本项目支持微信被动时限15s，一般问题不会超时，超时后端会缓存答案，可以稍后重新提问立即返回)
  - 可以直接api调用。(忽略下边有关公众号的配置即可)
- 说明
  - 是否免费。不是，但`OpenAI`账号赠送18$，限期使用。按字算钱，$0.002/1000 tokens，每次花费已经打印在日志里。
  - 没做上下文。OpenAI不记录会话，按字数算钱，上下文的实现其实是将之前的内容都作为参数调用，累积花费巨大。
  - 敏感词检测。加了[敏感词检测](https://github.com/tomatocuke/sieve)，代码内置隐藏了一些敏感词，你也可以启动时在根目录添加`keyword.txt`自定义敏感词。如有敏感词误杀，你可以向我反映。
- 体验。关注公众号`杠点杠`尝试提问，这仅是个人娱乐号，不推送。


### 部署
1. 获取`API_KEY`。[OpenAI](https://beta.openai.com/account/api-keys) （如果访问被拒绝，注意全局代理，打开调试，Application清除LocalStorage后刷新，实测可以）
2. 获取微信公众号`令牌Token`：[微信公众平台](https://mp.weixin.qq.com/)->基本配置->服务器配置->令牌(Token) 
3. 克隆项目，修改配置文件 `config.yaml`
4. 两种方式部署
  1. 直接二进制启动
    ```sh
    # mkdir log
    # 尝试启动
    ./openBin 
    # 守护进程 
    nohup ./openaiBin >> log/data.log 2>&1 &
    ```
  2. 使用Docker启动服务
    ```bash
    # 注意9001是配置默认的端口号，如果更改，注意容器内外端口映射，自己更改
    # 注意这里会拷贝配置到容器里，如果修改配置，需到容器内修改，或者启用新的容器
    docker run -d -p 80:9001 -v $PWD/log:/app/log -v $PWD/config.yaml:/app/config.yaml tomatocuke/openai
    # 查看状况
    docker logs 容器ID 
    ```
  
5. 验证服务 `curl 'http://127.0.0.1/test?msg=怎么做锅包肉'` ，查看日志 `tail -f log/data.log`
6. 公众号配置。 服务器地址(URL)填写 `http://服务器IP/wx`，设置明文方式传输，提交后，点击「启用」。 初次设置生效要等一会，过几分钟关闭再启用试试
    

### 三、其他
- 有什么问题我github可能不及时查看，欢迎提问和交流，QQ:`772532526`
