let express = require("express");
let app = express();

const Chain = require("@alipay/mychain/index.node") //在 node 环境使用 TLS 协议
const fs = require("fs")

const accountKey = fs.readFileSync("./resources/duncanwang-user.pem", { encoding: "utf8" })
const accountPassword = "2018ceshi"  //需要替换为自定义的 user.pem 密码

const keyInfo = Chain.utils.getKeyInfo(accountKey, accountPassword)
//可打印私钥和公钥，使用 16 进制
//console.log('private key:', keyInfo.privateKey.toString('hex'))
//console.log('public key:', keyInfo.publicKey.toString('hex'))

const passphrase = "2018ceshi" //需要替换为自定义的 client.key 密码
//配置选项
let opt = {
    host: '139.196.136.94',    //目标区块链网络节点的 IP
    port: 18130,          //端口号
    timeout: 30000,       //连接超时时间配置
    cert: fs.readFileSync("./resources/client.crt", { encoding: "utf8" }),
    ca: fs.readFileSync("./resources/ca.crt", { encoding: "utf8" }),
    key: fs.readFileSync("./resources/client.key", { encoding: "utf8" }),
    userPublicKey: keyInfo.publicKey,
    userPrivateKey: keyInfo.privateKey,
    userRecoverPublicKey: keyInfo.publicKey,
    userRecoverPrivateKey: keyInfo.privateKey,
    passphrase: passphrase
}

//初始化一个连接实例
const chain = Chain(opt)

//调用 API 查询最新的一个区块数据
chain.ctr.QueryLastBlock({}, (err, data) => {
    // console.log('raw data:', data)                                     //区块结构数据
    // console.log('block hash:', data.block.block_header.hash)             //区块哈希
    // console.log('block number:', data.block.block_header.block_number) //区块高度
})

//设置ABI信息
const abi =
    [{"constant":true,"inputs":[],"name":"getInfo","outputs":[{"name":"","type":"string"},{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_name","type":"string"},{"name":"_age","type":"uint256"}],"name":"setInfo","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"anonymous":false,"inputs":[{"indexed":false,"name":"name","type":"string"},{"indexed":false,"name":"age","type":"uint256"}],"name":"Instructor","type":"event"}]
const contractName = "name-age";
const bytecode = "0x608060405234801561001057600080fd5b506103be806100206000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635a9b0b89146100515780638262963b146100e8575b600080fd5b34801561005d57600080fd5b5061006661015b565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156100ac578082015181840152602081019050610091565b50505050905090810190601f1680156100d95780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b3480156100f457600080fd5b50610159600480360381019080803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929080359060200190929190505050610207565b005b6060600080600154818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101f85780601f106101cd576101008083540402835291602001916101f8565b820191906000526020600020905b8154815290600101906020018083116101db57829003601f168201915b50505050509150915091509091565b816000908051906020019061021d9291906102ed565b50806001819055507f010becc10ca1475887c4ec429def1ccc2e9ea1713fe8b0d4e9a1d009042f6b8e600060015460405180806020018381526020018281038252848181546001816001161561010002031660029004815260200191508054600181600116156101000203166002900480156102da5780601f106102af576101008083540402835291602001916102da565b820191906000526020600020905b8154815290600101906020018083116102bd57829003601f168201915b5050935050505060405180910390a15050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061032e57805160ff191683800117855561035c565b8280016001018555821561035c579182015b8281111561035b578251825591602001919060010190610340565b5b509050610369919061036d565b5090565b61038f91905b8082111561038b576000816000905550600101610373565b5090565b905600a165627a7a723058208ecb5a3721f4deee06f2f384b8ba7b90a47f803f1acbe2ad128b2eebc045bb240029";

// 初始化一个合约实例
let myContract = chain.ctr.contract(contractName, abi)

// 部署合约，可传递初始化函数需要的参数
/*
myContract.new(bytecode, {
  from: 'duncanwang',
  // parameters: [param1, param2]
}, (err, contract, data) => {
  console.log(data)
})*/

//调用合约getInfo函数，查看当前用户的姓名和年龄
// myContract.getInfo( { from: 'duncanwang' }, (err, name, age) => {
//     console.log('output is:', name, age)
//   })

//调用合约getInfo函数，查看当前用户的姓名和年龄
// myContract.setInfo( "duncanwang", 20,{ from: 'duncanwang' }, (err,data1,data2) => {
//     console.log('output1 is------>:', data1)
//     console.log('output2 is------>:', data2)
//   })

// 调用合约getInfo函数，查看当前用户的姓名和年龄
// myContract.getInfo( { from: 'duncanwang' }, (err, name, age) => {
//     console.log('output is:', name, age)
//   })



//初始返回一个home页面
app.get("/", function(req ,res) {
    res.render("home.ejs",{
        name: "",
        info: ''
    });
});

//更新接口
app.get("/update", function(req, res){
    myContract.setInfo( req.query.fname, req.query.age >> 0,{ from: 'duncanwang' }, (err,data) => {
        myContract.getInfo( { from: "duncanwang" }, (err, name, age) => {
            console.log('output is:', name)
            res.render("home.ejs",{
                name: name,
                info: '更新成功'
            });
        })
    })
});
//获取接口
app.get("/search", function(req ,res) {
    myContract.getInfo( { from: "duncanwang" }, (err, name, age) => {
        res.render("home.ejs",{
            name: name,
            info: '获取成功'
        });
    })
});

let server = require('http').createServer(app);
server.listen(5000);{
    console.log("Sever Ready! open on http://localhost:5000");
}