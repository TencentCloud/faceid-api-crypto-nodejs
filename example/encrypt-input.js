// 仅对请求入参进行加密
// 引入sdk包
const { encrypt, init, Algorithm } = require('../src/index')
const { SM2PublicKey } = require('./consts')

/**
 * 初始化，此处需要传入非对称加密用的公钥，使用的算法
 * 算法支持:
 *   1. Algorithm.AES256CBC: 对称加密使用AES256CBC，非对称加密使用RSA
 *   2. Algorithm.SM4GCM: 对称加密使用SM4GCM，非对称加密使用SM2
 * 第3个参数为对称密钥的缓存时间，单位ms
 */
init(SM2PublicKey, Algorithm.SM4GCM, 5000)

/**
 * 入参1, 传入API3.0的请求结构体，本方法会自动填充`Encryption`字段
 * 入参2, 传入需要加密传输的字段名，API3.0接口文档会描述清楚本接口支持加密哪些字段
 */
const [encryptReq] = encrypt({
  IdCard: '440111111111111111',
  Name: '爱新觉罗永琪',
  RuleId: '2'
}, ['IdCard', 'Name'])

/**
 * 发送处理后的req
 */
console.log(JSON.stringify(encryptReq))

// 此处mock一个
const rsp = {}

/**
 * 请求完成后，可以直接使用此对象
 */
console.log(rsp)
