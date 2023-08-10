// 对请求入参、出参进行加密
// 引入sdk包
const { encrypt, init, Algorithm, decrypt } = require('../src/index')
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
 * 保存好返回的明文对称密钥，后续解密回包需要使用
 */
const [encryptReq, plainSEK] = encrypt({
  IdCard: '440111111111111111',
  Name: '爱新觉罗永琪',
  RuleId: '2',
  BizToken: '37C8960C-4673-4152-8122-1433C305C144'
}, ['IdCard', 'Name'])

/**
 * 发送处理后的req，获得回包rsp
 */
console.log(JSON.stringify(encryptReq))
console.log('plainSEK', plainSEK.toString('base64'))

// 此处mock一个，rsp一定带有Encryption字段。
const rsp = {
  Response: {
    Encryption: {
      Algorithm: 'SM4-GCM',
      CiphertextBlob: 'BC3JNqinBaASuOhjP/WCkrCgtLm03d/stJMh1QgPKfdFoVdpySbZNah6iUIhoSI+EPML8dDgXJE2wkSZv8x029v+t2VoC6Lc6RW1gowi2tqwz2SNmb4qN/VrqMi1a3m/T3gXY42AbvORP90Jxqgr3hE=',
      EncryptList: [
        'Response.Text.IdCard',
        'Response.Text.Name'
      ],
      Iv: 'cHNm8k09p2d80owr',
      TagList: [
        'meBiloynTRhQtOtLR2xccQ==',
        'Anrq6V9s4jwBg+/mxW9Zeg=='
      ]
    },
    Text: {
      IdCard: 'oUfaRWLLjR9MclkyFF68M7Ot',
      Name: 'cvtbksVKVIn0pNWUw9815RI2'
    }
  }
}

/**
 * 将rsp对象传入，同时将明文密钥也传入，此方法会修改rsp对象本身，将需要解密的数据解密并替换完成
 */
decrypt(rsp, Buffer.from('t/dlVGSD3hMbSG21ocAylQ==', 'base64'))

/**
 * 解密完成后，可以直接使用此对象
 */
console.log(rsp)
