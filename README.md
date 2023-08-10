# faceid-api-crypto-nodejs

faceid产品中所有接口的出入参加密解密工具。

## 用法
0. 初始化
```
init(publicKey,alg,keyExpire)
```

1. 仅入参需要加密
```
encrypt(req,fields)
```

2. 仅出参需要加密
```
req, plaintextKey = encrypt(req,[])
rsp = send(req)
decrypt(rsp,plaintextKey)
```

3. 出入参都需要加密
```
req, plaintextKey = encrypt(req,fields)
rsp = send(req)
decrypt(rsp,plaintextKey)
```

更详细的用法，详见example