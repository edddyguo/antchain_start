package com.example.demo;

import com.alipay.mychain.sdk.api.callback.IEventCallback;
import com.alipay.mychain.sdk.api.logging.AbstractLoggerFactory;
import com.alipay.mychain.sdk.api.logging.ILogger;
import com.alipay.mychain.sdk.api.utils.ConfidentialUtil;
import com.alipay.mychain.sdk.api.utils.Utils;
import com.alipay.mychain.sdk.common.VMTypeEnum;
import com.alipay.mychain.sdk.crypto.MyCrypto;
import com.alipay.mychain.sdk.crypto.hash.Hash;
import com.alipay.mychain.sdk.crypto.keyoperator.Pkcs8KeyOperator;
import com.alipay.mychain.sdk.crypto.keypair.Keypair;
import com.alipay.mychain.sdk.crypto.signer.SignerBase;
import com.alipay.mychain.sdk.domain.account.Identity;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import com.alipay.mychain.sdk.api.MychainClient;
import com.alipay.mychain.sdk.api.env.ClientEnv;
import com.alipay.mychain.sdk.api.env.ISslOption;
import com.alipay.mychain.sdk.api.env.SignerOption;
import com.alipay.mychain.sdk.api.env.SslBytesOption;
import com.alipay.mychain.sdk.domain.event.EventModelType;
import com.alipay.mychain.sdk.domain.transaction.Transaction;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.Message;
import com.alipay.mychain.sdk.message.event.PushAccountEvent;
import com.alipay.mychain.sdk.message.query.QueryTransactionResponse;
import com.alipay.mychain.sdk.message.transaction.AbstractTransactionRequest;
import com.alipay.mychain.sdk.message.transaction.TransactionReceiptResponse;
import com.alipay.mychain.sdk.message.transaction.confidential.ConfidentialRequest;
import com.alipay.mychain.sdk.message.transaction.contract.CallContractRequest;
import com.alipay.mychain.sdk.message.transaction.contract.DeployContractRequest;
import com.alipay.mychain.sdk.type.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.utils.ByteUtils;
import com.alipay.mychain.sdk.utils.IOUtil;
import com.alipay.mychain.sdk.utils.RandomUtil;
import com.alipay.mychain.sdk.vm.EVMOutput;
import com.alipay.mychain.sdk.vm.EVMParameter;

public class Demo {
    /**
     * contract code
     */
    private static String contractCodeString
            =
            "6080604052633b9aca00600055600060015534801561001d57600080fd5b5033600281905550610492806100346000396000f3006080604"
                    +
                    "05260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063"
                    +
                    "af7c102c1461005c578063b2628df81461009d578063d4486019146100ec575b600080fd5b34801561006857600080fd5b5061008"
                    +
                    "76004803603810190808035906020019092919050505061013b565b6040518082815260200191505060405180910390f35b348015"
                    +
                    "6100a957600080fd5b506100d26004803603810190808035906020019092919080359060200190929190505050610158565b60405"
                    +
                    "1808215151515815260200191505060405180910390f35b3480156100f857600080fd5b5061012160048036038101908080359060"
                    +
                    "200190929190803590602001909291905050506102d8565b604051808215151515815260200191505060405180910390f35b60006"
                    +
                    "0036000838152602001908152602001600020549050919050565b6000600254331415156101d3576040517f08c379a00000000000"
                    +
                    "000000000000000000000000000000000000000000000081526004018080602001828103825260118152602001807f5065726d697"
                    +
                    "373696f6e2064656e69656400000000000000000000000000000081525060200191505060405180910390fd5b6000548260015401"
                    +
                    "131580156101ee57506001548260015401135b80156101fa5750600082135b151561026e576040517f08c379a0000000000000000"
                    +
                    "00000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c696420"
                    +
                    "76616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b816003600085815260200"
                    +
                    "190815260200160002060008282540192505081905550816001600082825401925050819055508183337f31a52246bf8c995cecfd"
                    +
                    "d5404cf290ae6c2f4e174e888e4de4fd208137ec274d60405160405180910390a46001905092915050565b6000816003600033815"
                    +
                    "26020019081526020016000205412151515610365576040517f08c379a00000000000000000000000000000000000000000000000"
                    +
                    "000000000081526004018080602001828103825260138152602001807f62616c616e6365206e6f7420656e6f75676821000000000"
                    +
                    "0000000000000000081525060200191505060405180910390fd5b60008213801561037757506000548213155b15156103eb576040"
                    +
                    "517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e815"
                    +
                    "2602001807f496e76616c69642076616c756521000000000000000000000000000000000000815250602001915050604051809103"
                    +
                    "90fd5b816003600033815260200190815260200160002060008282540392505081905550816003600085815260200190815260200"
                    +
                    "1600020600082825401925050819055508183337f97c0c2106db19ca3c64afdc86820cd157d60361f777bf0e5323254d6c9689550"
                    +
                    "60405160405180910390a460009050929150505600a165627a7a72305820371af9e83b0e49ca71634c470c75e504d08db9abbaf39"
                    + "92f30434f8d7a7994d40029";

    private static String contractCodeString1="60806040523480156100115760006000fd5b505b6040518060400160405280600c81526020017f48656c6c6f20776f726c642100000000000000000000000000000000000000008152602001506000600050908051906020019061006492919061006b565b505b61011b565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100ac57805160ff19168380011785556100df565b828001600101855582156100df579182015b828111156100de57825182600050909055916020019190600101906100be565b5b5090506100ec91906100f0565b5090565b61011891906100fa565b8082111561011457600081815060009055506001016100fa565b5090565b90565b6101c58061012a6000396000f3fe60806040523480156100115760006000fd5b506004361061003b5760003560e01c806319ff1d2114610041578063f8a8fd6d146100cc5761003b565b60006000fd5b6100496100d6565b6040518083815260200180602001828103825283818151815260200191508051906020019080838360005b838110156100905780820151818401525b602081019050610074565b50505050905090810190601f1680156100bd5780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b6100d461018c565b005b60006060336000600050819150808054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101785780601f1061014d57610100808354040283529160200191610178565b820191906000526020600020905b81548152906001019060200180831161015b57829003601f168201915b5050505050905091509150610188565b9091565b5b56fea26469706673582212205ee23d345d237d06b1c7766ea630d97b625c1b1829ba7075ee09f5594d6d2fb564736f6c63430006040033";
    private static byte[] contractCode = ByteUtils.hexStringToBytes(contractCodeString);

    private static String contractCodeStringV2="60806040523480156100115760006000fd5b505b6040518060400160405280600c81526020017f48656c6c6f20776f726c642100000000000000000000000000000000000000008152602001506000600050908051906020019061006492919061006b565b505b61011b565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100ac57805160ff19168380011785556100df565b828001600101855582156100df579182015b828111156100de57825182600050909055916020019190600101906100be565b5b5090506100ec91906100f0565b5090565b61011891906100fa565b8082111561011457600081815060009055506001016100fa565b5090565b90565b6101c58061012a6000396000f3fe60806040523480156100115760006000fd5b506004361061003b5760003560e01c806319ff1d2114610041578063f8a8fd6d146100cc5761003b565b60006000fd5b6100496100d6565b6040518083815260200180602001828103825283818151815260200191508051906020019080838360005b838110156100905780820151818401525b602081019050610074565b50505050905090810190601f1680156100bd5780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b6100d461018c565b005b60006060336000600050819150808054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101785780601f1061014d57610100808354040283529160200191610178565b820191906000526020600020905b81548152906001019060200180831161015b57829003601f168201915b5050505050905091509150610188565b9091565b5b56fea26469706673582212205ee23d345d237d06b1c7766ea630d97b625c1b1829ba7075ee09f5594d6d2fb564736f6c63430006040033";
    private static byte[] contractCodev2 = ByteUtils.hexStringToBytes(contractCodeStringV2);
    /**
     * contract id
     */
    private static String testContractId = "CreditManager" + System.currentTimeMillis();

    /**
     * baas上创建的帐户名字
     */
    private static final String account = "mason0001";//
    private static Identity userIdentity;
    private static Keypair userKeypair;

    /**
     * create account test
     */
    private static Identity testAccount1 = Utils.getIdentityByName("test_account_" + System.currentTimeMillis());
    /**
     * sdk client
     */
    private static MychainClient sdk;
    /**
     * client key password
     */
    private static String keyPassword = "Zhxc6545398@";  //根据实际情况更新，申请证书时候指定的SSL密码
    /**
     * user password
     */
    private static String userPassword = "Zhxc6545398@"; //根据实际情况更新。申请证书时，创建账户的密码
    /**
     * host ip
     */
    //47.103.163.48
    //47.103.111.18
    private static String host = "47.103.163.48"; //根据实际情况更新，在BaaS平台，通过查看目标合约链"详情"，在"区块浏览器"中查看"节点详情"可获取链节点的 IP地址 和 端口号。

    /**
     * server port
     */
    private static int port = 18130;               //根据实际情况更新
    /**
     * trustCa password.
     */
    private static String trustStorePassword = "mychain";
    /**
     * mychain environment
     */
    private static ClientEnv env;
    /**
     * mychain is tee Chain
     */
    private static boolean isTeeChain = false;
    /**
     * tee chain publicKeys
     */
    private static List<byte[]> publicKeys = new ArrayList<byte[]>();
    /**
     * tee chain secretKey
     */
    private static String secretKey = "123456";


    private static void exit(String tag, String msg) {
        exit(String.format("%s error : %s ", tag, msg));
    }

    private static void exit(String msg) {
        System.out.println(msg);
        System.exit(0);
    }

    private static String getErrorMsg(int errorCode) {
        int minMychainSdkErrorCode = ErrorCode.SDK_INTERNAL_ERROR.getErrorCode();
        if (errorCode < minMychainSdkErrorCode) {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        } else {
            return ErrorCode.valueOf(errorCode).getErrorDesc();
        }
    }

    private static void initMychainEnv() throws IOException {
        // any user key for sign message
        String userPrivateKeyFile = "user.key";
        userIdentity = Utils.getIdentityByName(account); //根据实际情况更新'gushui03'为'user.key'对应的账户名(BaaS申请证书时创建的账户名)
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(com.example.demo.DemoSample.class.getClassLoader().getResourceAsStream(userPrivateKeyFile)), userPassword);

        // use publicKeys by tee
        if (isTeeChain) {
            Keypair keypair = new Pkcs8KeyOperator()
                    .loadPubkey(
                            IOUtil.inputStreamToByte(com.example.demo.DemoSample.class.getClassLoader().getResourceAsStream("test_seal_pubkey.pem")));
            byte[] publicKeyDer = keypair.getPubkeyEncoded(); //tee_rsa_public_key.pem 从BaaS下载获取
            publicKeys.add(publicKeyDer);
        }
        env = buildMychainEnv();
        ILogger logger = AbstractLoggerFactory.getInstance(com.example.demo.DemoSample.class);
        env.setLogger(logger);
    }

    private static ClientEnv buildMychainEnv() throws IOException {
        InetSocketAddress inetSocketAddress = InetSocketAddress.createUnresolved(host, port);
        String keyFilePath = "client.key";
        String certFilePath = "client.crt";
        String trustStoreFilePath = "trustCa";

        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(IOUtil.inputStreamToByte(com.example.demo.DemoSample.class.getClassLoader().getResourceAsStream(keyFilePath)))
                .certBytes(IOUtil.inputStreamToByte(com.example.demo.DemoSample.class.getClassLoader().getResourceAsStream(certFilePath)))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        IOUtil.inputStreamToByte(com.example.demo.DemoSample.class.getClassLoader().getResourceAsStream(trustStoreFilePath)))
                .build();

        List<InetSocketAddress> socketAddressArrayList = new ArrayList<InetSocketAddress>();
        socketAddressArrayList.add(inetSocketAddress);

        List<SignerBase> signerBaseList = new ArrayList<SignerBase>();
        SignerBase signerBase = MyCrypto.getInstance().createSigner(userKeypair);
        signerBaseList.add(signerBase);
        SignerOption signerOption = new SignerOption();
        signerOption.setSigners(signerBaseList);

        return ClientEnv.build(socketAddressArrayList, sslOption, signerOption);
    }


    private static void signRequest(AbstractTransactionRequest request) {
        // sign request
        long ts = sdk.getNetwork().getSystemTimestamp();
        request.setTxTimeNonce(ts, BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger
                .valueOf(RandomUtil.randomize(ts + request.getTransaction().hashCode())), true);
        request.complete();
        sdk.getConfidentialService().signRequest(env.getSignerOption().getSigners(), request);
    }

    private static void deployContract() {
        EVMParameter contractParameters = new EVMParameter();

        // build DeployContractRequest
        DeployContractRequest request = new DeployContractRequest(userIdentity,
                Utils.getIdentityByName(testContractId), contractCode, VMTypeEnum.EVM,
                contractParameters, BigInteger.ZERO);

        TransactionReceiptResponse deployContractResult;
        if (isTeeChain) {
            signRequest(request);

            // generate transaction key
            byte[] transactionKey = ConfidentialUtil.keyGenerate(secretKey,
                    request.getTransaction().getHash().getValue());

            ConfidentialRequest confidentialRequest = new ConfidentialRequest(request, publicKeys, transactionKey);

            deployContractResult = sdk.getConfidentialService().confidentialRequest(confidentialRequest);
        } else {
            deployContractResult = sdk.getContractService().deployContract(request);
        }

        // deploy contract
        if (!deployContractResult.isSuccess()
                || deployContractResult.getTransactionReceipt().getResult() != 0) {
            exit("deployContract",
                    getErrorMsg((int) deployContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("deploy contract success.");
        }
    }

    private static void issue() {
        EVMParameter parameters = new EVMParameter("Issue(identity,int256)");
        parameters.addIdentity(userIdentity);
        parameters.addUint(BigInteger.valueOf(100));

        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(userIdentity,
                Utils.getIdentityByName(testContractId), parameters, BigInteger.ZERO, VMTypeEnum.EVM);

        TransactionReceiptResponse callContractResult;
        if (isTeeChain) {
            signRequest(request);

            // generate transaction key
            byte[] transactionKey = ConfidentialUtil.keyGenerate(secretKey,
                    request.getTransaction().getHash().getValue());

            ConfidentialRequest confidentialRequest = new ConfidentialRequest(request, publicKeys, transactionKey);

            callContractResult = sdk.getConfidentialService().confidentialRequest(confidentialRequest);
        } else {
            callContractResult = sdk.getContractService().callContract(request);
        }

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("issue", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("issue success.");
        }
    }

    private static void transfer() {
        // contract parameters
        EVMParameter contractParameters = new EVMParameter("Transfer(identity,int256)");
        contractParameters.addIdentity(testAccount1);
        contractParameters.addUint(BigInteger.valueOf(50));

        CallContractRequest request = new CallContractRequest(userIdentity,
                Utils.getIdentityByName(testContractId), contractParameters, BigInteger.ZERO, VMTypeEnum.EVM);

        TransactionReceiptResponse callContractResult;
        if (isTeeChain) {
            signRequest(request);

            // generate transaction key
            byte[] transactionKey = ConfidentialUtil.keyGenerate(secretKey,
                    request.getTransaction().getHash().getValue());

            ConfidentialRequest confidentialRequest = new ConfidentialRequest(request, publicKeys, transactionKey);

            callContractResult = sdk.getConfidentialService().confidentialRequest(confidentialRequest);
        } else {
            callContractResult = sdk.getContractService().callContract(request);
        }

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("transfer", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("transfer success.");
        }
    }

    private static BigInteger query(Identity account) {
        // contract parameters
        EVMParameter parameters = new EVMParameter("Query(identity)");
        parameters.addIdentity(account);

        // build call contract request
        CallContractRequest request = new CallContractRequest(userIdentity,
                Utils.getIdentityByName(testContractId), parameters, BigInteger.ZERO, VMTypeEnum.EVM);

        TransactionReceiptResponse callContractResult;
        if (isTeeChain) {
            signRequest(request);

            // generate transaction key
            byte[] transactionKey = ConfidentialUtil.keyGenerate(secretKey,
                    request.getTransaction().getHash().getValue());

            ConfidentialRequest confidentialRequest = new ConfidentialRequest(request, publicKeys, transactionKey);

            callContractResult = sdk.getConfidentialService().confidentialRequest(confidentialRequest);
        } else {
            callContractResult = sdk.getContractService().callContract(request);
        }

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("query", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        }

        byte[] output = null;
        if (isTeeChain) {
            output = ConfidentialUtil.decrypt(secretKey, callContractResult.getTransactionReceipt().getOutput(), request.getTransaction().getHash().hexStrValue());
        } else {
            output = callContractResult.getTransactionReceipt().getOutput();
        }

        if (output == null) {
            exit("decrypt tee", "decrypt tee output failed");
            return BigInteger.ZERO;
        }

        // decode return values
        EVMOutput contractReturnValues = new EVMOutput(ByteUtils.toHexString(output));
        return contractReturnValues.getUint();
    }

    private static void expect(BigInteger balance, BigInteger expectBalance) {
        if (balance.compareTo(expectBalance) != 0) {
            exit("expect", "the account value is not expected.");
        } else {
            System.out.println("check account balance success.");
        }
    }

    private static void initSdk() {
        sdk = new MychainClient();
        boolean initResult = sdk.init(env);
        if (!initResult) {
            exit("initSdk", "sdk init failed.");
        }
    }

    public static void queryTransaction(Hash txHash) {
        //创建一个交易，以转账为例
//        TransferBalanceRequest transferBalanceRequest = new TransferBalanceRequest(Utils.getIdentityByName("Administrator"),
//                Utils.getIdentityByName("Tester001"), BigInteger.valueOf(100));
//        TransferBalanceResponse transferBalanceResponse = sdk.getAccountService().transferBalance(transferBalanceRequest);
//        if (!transferBalanceResponse.isSuccess()) {
//            //打印
//           // logger.error("transferBalance failed, errorCode :{}, errorDesc: {}", transferBalanceResponse.getErrorCode().getErrorCode(), transferBalanceResponse.getErrorCode().getErrorDesc());
//        } else {
//            // 交易收据
//            TransactionReceipt transactionReceipt = transferBalanceResponse.getTransactionReceipt();
//            if (transactionReceipt.getResult() != 0) {
//             //   logger.error("transferBalance failed, errorCode :{}, errorDesc: {}", ErrorCode.valueOf((int) transactionReceipt.getResult()).getErrorCode(), ErrorCode.valueOf((int) transactionReceipt.getResult()).getErrorDesc());
//            } else {
//               // logger.info("transferBalance success.返回信息: {}", transactionReceipt.toString());
//            }
//        }

        QueryTransactionResponse queryTransactionResponse = sdk.getQueryService().queryTransaction(txHash);
        if (!queryTransactionResponse.isSuccess()) {
            //logger.error("queryTransaction failed, errorCode :{}, errorDesc: {}", queryTransactionResponse.getErrorCode().getErrorCode(), queryTransactionResponse.getErrorCode().getErrorDesc());
        } else {
            Transaction transaction = queryTransactionResponse.getTransaction();
            //打印 transaction
            System.out.println("queryTransaction success.返回信息: " + transaction.toString());
        }
    }
    //订阅账户合约事件 MyAssetSample0011
    public static void getEvent(){
        // event handler
        IEventCallback handler = new IEventCallback() {
            @Override
            public void onEvent(Message message) {
                PushAccountEvent accountEvent = (PushAccountEvent) message;
                //code
                System.out.println("getEvent success.返回信息: " + accountEvent.toString());
            }
        };
        // account: Tester001
        Identity identity = new Identity("0xf255251596447908eea42b22be8ea73005003553fc548db061afe16acec9e150");
        // listen account
        BigInteger eventId = sdk.getEventService().listenAccount(identity, handler, EventModelType.PULL);
        if (eventId.longValue() == 0) {
            System.out.println("listen failed++++++++++++++++++++++++++++++");
        } else {
            System.out.println("listen success, eventId:++++++++++++++++++++++++++++++ " + eventId);
        }
    }



    public static void main(String[] args) throws Exception {
        //step 1:init mychain env.
        initMychainEnv();

//        //step 2: init sdk client
        initSdk();
//
//        //step 3 : deploy a contract using useridentity.
     //   deployContract();
//
////        //step 4 issue 100 assets to testAccount1.
//        issue();
////
////        //step 5 : transfer 50 assets from useridentity to testAccount1
//        transfer();
////
////        //step 6 : query testAccount1 whose balance should be 50.
//        BigInteger balance = query(testAccount1);
////
////        //step 7 : compare to expect balance.
//        expect(balance, BigInteger.valueOf(50));
////

        //初始化hash
        //    queryTransaction(new Hash("0x205276d41f6495a2db0fa68f2d4aa4f27277e2b49872468ce91c7e8877bd92fd"));

//        getEvent();
////
////        //step 8 : sdk shut down

        // 部署调用hello 合约
        deployHelloContract(contractCodev2);



        sdk.shutDown();
    }

    private static void deployHelloContract(byte[] contractCode) {
        EVMParameter contractParameters = new EVMParameter();

        // build DeployContractRequest
        DeployContractRequest request = new DeployContractRequest(userIdentity,
                Utils.getIdentityByName(testContractId), contractCode, VMTypeEnum.EVM,
                contractParameters, BigInteger.ZERO);

        TransactionReceiptResponse deployContractResult;
        if (isTeeChain) {
            signRequest(request);

            // generate transaction key
            byte[] transactionKey = ConfidentialUtil.keyGenerate(secretKey,
                    request.getTransaction().getHash().getValue());

            ConfidentialRequest confidentialRequest = new ConfidentialRequest(request, publicKeys, transactionKey);

            deployContractResult = sdk.getConfidentialService().confidentialRequest(confidentialRequest);
        } else {
            deployContractResult = sdk.getContractService().deployContract(request);
        }

        // deploy contract
        if (!deployContractResult.isSuccess()
                || deployContractResult.getTransactionReceipt().getResult() != 0) {
            exit("deployContract",
                    getErrorMsg((int) deployContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("deploy contract success.");
        }
    }
}




