// 仅对请求出参进行加密
// 引入sdk包
const { encrypt, init, Algorithm, decrypt } = require('../src/index')
const { RsaPublicKey } = require('./consts')

/**
 * 初始化，此处需要传入非对称加密用的公钥，使用的算法
 * 算法支持:
 *   1. Algorithm.AES256CBC: 对称加密使用AES256CBC，非对称加密使用RSA
 *   2. Algorithm.SM4GCM: 对称加密使用SM4GCM，非对称加密使用SM2
 * 第3个参数为对称密钥的缓存时间，单位ms
 */
init(RsaPublicKey, Algorithm.AES256CBC, 5000)

/**
 * 入参1, 传入API3.0的请求结构体，本方法会自动填充`Encryption`字段
 * 入参2, 不需要传入
 * 保存好返回的明文对称密钥，后续解密回包需要使用
 */
const [encryptReq, plainSEK] = encrypt({
  RuleId: '2',
  BizToken: '37C8960C-4673-4152-8122-1433C305C144'
}, [])

/**
 * 发送处理后的req，获得回包rsp
 */
console.log(JSON.stringify(encryptReq))
console.log('plainSEK', plainSEK.toString('base64'))

// 此处mock一个，rsp一定带有Encryption字段。
const rsp = {
  Response: {
    Encryption: {
      Algorithm: 'AES-256-CBC',
      CiphertextBlob: 'DCaa541gYPA8ybDaAasY4C17K5CHo3s8/ZDNsaS8hH8Gr+qnA9RY53QswVOY4smcJsv5ToXPN6qOqruT9QVw5VPVglQ5YO60RjWabZKA+sF3BxDRMmrnuTKMNPwswen1mG4SfotyJ4IVv4PHomPZwzlZtGjm0CkXvgmnaHLxkck=',
      EncryptList: [
        'Response.Text.IdCard',
        'Response.Text.Name'
      ],
      Iv: 'vTjCqg1Xz6Lh0pJZCNjAAQ==',
      TagList: []
    },
    RequestId: 'd55782f3-dc0f-4484-a067-ff2046fe659e',
    Text: {
      IdCard: '8TEJyC4YWALmK5U9cw+R+1Rvs4LuNRAAm8LQkwrJEa4=',
      Name: 'QR3meQHDzArXCIuJIyETLzRtOjg0vjRxcYdKQTOE7vw='
    }
  }
}

/**
 * 将rsp对象传入，同时将明文密钥也传入，此方法会修改rsp对象本身，将需要解密的数据解密并替换完成
 */
decrypt(rsp, Buffer.from('XJKXDwFwoYHoORb/g1ReMJ+POptUa7Ax4R+CRI0GLgU=', 'base64'))

/**
 * 解密完成后，可以直接使用此对象
 */
console.log(rsp)
