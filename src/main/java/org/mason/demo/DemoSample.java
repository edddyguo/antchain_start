package com.example.demo;

import com.alipay.mychain.sdk.api.callback.IEventCallback;
import com.alipay.mychain.sdk.api.logging.AbstractLoggerFactory;
import com.alipay.mychain.sdk.api.logging.ILogger;
import com.alipay.mychain.sdk.api.utils.ConfidentialUtil;
import com.alipay.mychain.sdk.api.utils.Utils;
import com.alipay.mychain.sdk.common.VMTypeEnum;
import com.alipay.mychain.sdk.crypto.MyCrypto;
import com.alipay.mychain.sdk.crypto.PublicKey;
import com.alipay.mychain.sdk.crypto.hash.Hash;
import com.alipay.mychain.sdk.crypto.hash.HashFactory;
import com.alipay.mychain.sdk.crypto.hash.IHash;
import com.alipay.mychain.sdk.crypto.keyoperator.Pkcs8KeyOperator;
import com.alipay.mychain.sdk.crypto.keypair.Keypair;
import com.alipay.mychain.sdk.crypto.signer.SignerBase;
import com.alipay.mychain.sdk.domain.account.Account;
import com.alipay.mychain.sdk.domain.account.AccountStatus;
import com.alipay.mychain.sdk.domain.account.AuthMap;
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
import com.alipay.mychain.sdk.domain.transaction.TransactionReceipt;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.Message;
import com.alipay.mychain.sdk.message.event.PushAccountEvent;
import com.alipay.mychain.sdk.message.event.PushTopicsEvent;
import com.alipay.mychain.sdk.message.query.QueryTransactionResponse;
import com.alipay.mychain.sdk.message.status.QueryNodeMetricsStatusResponse;
import com.alipay.mychain.sdk.message.transaction.AbstractTransactionRequest;
import com.alipay.mychain.sdk.message.transaction.TransactionReceiptResponse;
import com.alipay.mychain.sdk.message.transaction.account.CreateAccountRequest;
import com.alipay.mychain.sdk.message.transaction.account.CreateAccountResponse;
import com.alipay.mychain.sdk.message.transaction.confidential.ConfidentialRequest;
import com.alipay.mychain.sdk.message.transaction.contract.CallContractRequest;
import com.alipay.mychain.sdk.message.transaction.contract.DeployContractRequest;
import com.alipay.mychain.sdk.message.transaction.contract.UpdateContractRequest;
import com.alipay.mychain.sdk.message.transaction.contract.UpdateContractResponse;
import com.alipay.mychain.sdk.type.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.utils.ByteUtils;
import com.alipay.mychain.sdk.utils.IOUtil;
import com.alipay.mychain.sdk.utils.RandomUtil;
import com.alipay.mychain.sdk.vm.EVMOutput;
import com.alipay.mychain.sdk.vm.EVMParameter;
import org.mason.demo.Helper;

public class DemoSample {
    //导入帮助类
    private static Helper helper ;

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

    private static byte[] contractCode = ByteUtils.hexStringToBytes(contractCodeString);

    private static final String contractCodeString1="0x608060405234801561001057600080fd5b50610400806100206000396000f300608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635a9b0b891461005c5780638262963b146100f3578063d5dcf12714610166575b600080fd5b34801561006857600080fd5b50610071610193565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156100b757808201518184015260208101905061009c565b50505050905090810190601f1680156100e45780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b3480156100ff57600080fd5b50610164600480360381019080803590602001908201803590602001908080601f01602080910402602001604051908101604052809392919081815260200183838082843782019150505050505091929192908035906020019092919050505061023f565b005b34801561017257600080fd5b5061019160048036038101908080359060200190929190505050610325565b005b6060600080600154818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156102305780601f1061020557610100808354040283529160200191610230565b820191906000526020600020905b81548152906001019060200180831161021357829003601f168201915b50505050509150915091509091565b816000908051906020019061025592919061032f565b50806001819055507f010becc10ca1475887c4ec429def1ccc2e9ea1713fe8b0d4e9a1d009042f6b8e600060015460405180806020018381526020018281038252848181546001816001161561010002031660029004815260200191508054600181600116156101000203166002900480156103125780601f106102e757610100808354040283529160200191610312565b820191906000526020600020905b8154815290600101906020018083116102f557829003601f168201915b5050935050505060405180910390a15050565b8060018190555050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061037057805160ff191683800117855561039e565b8280016001018555821561039e579182015b8281111561039d578251825591602001919060010190610382565b5b5090506103ab91906103af565b5090565b6103d191905b808211156103cd5760008160009055506001016103b5565b5090565b905600a165627a7a723058201cceaa0bfe1387d67b75238a941644d49898607704b3d6fded2cd2ae566488bf0029";

    //helloV1
    private static byte[] contractCode1 = ByteUtils.hexStringToBytes(contractCodeString1);

    //v2
    private static final String contractCodeStringV2="0x608060405234801561001057600080fd5b5061065a806100206000396000f300608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635a9b0b89146100675780638262963b146100fe57806385b31d7b14610171578063b1899c4114610208575b600080fd5b34801561007357600080fd5b5061007c61029f565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156100c25780820151818401526020810190506100a7565b50505050905090810190601f1680156100ef5780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b34801561010a57600080fd5b5061016f600480360381019080803590602001908201803590602001908080601f01602080910402602001604051908101604052809392919081815260200183838082843782019150505050505091929192908035906020019092919050505061034b565b005b34801561017d57600080fd5b50610186610431565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156101cc5780820151818401526020810190506101b1565b50505050905090810190601f1680156101f95780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b34801561021457600080fd5b5061021d6104dd565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b83811015610263578082015181840152602081019050610248565b50505050905090810190601f1680156102905780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b6060600080600154818054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561033c5780601f106103115761010080835404028352916020019161033c565b820191906000526020600020905b81548152906001019060200180831161031f57829003601f168201915b50505050509150915091509091565b8160009080519060200190610361929190610589565b50806001819055507f010becc10ca1475887c4ec429def1ccc2e9ea1713fe8b0d4e9a1d009042f6b8e6000600154604051808060200183815260200182810382528481815460018160011615610100020316600290048152602001915080546001816001161561010002031660029004801561041e5780601f106103f35761010080835404028352916020019161041e565b820191906000526020600020905b81548152906001019060200180831161040157829003601f168201915b5050935050505060405180910390a15050565b6060600080600154818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156104ce5780601f106104a3576101008083540402835291602001916104ce565b820191906000526020600020905b8154815290600101906020018083116104b157829003601f168201915b50505050509150915091509091565b6060600080600154818054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561057a5780601f1061054f5761010080835404028352916020019161057a565b820191906000526020600020905b81548152906001019060200180831161055d57829003601f168201915b50505050509150915091509091565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106105ca57805160ff19168380011785556105f8565b828001600101855582156105f8579182015b828111156105f75782518255916020019190600101906105dc565b5b5090506106059190610609565b5090565b61062b91905b8082111561062757600081600090555060010161060f565b5090565b905600a165627a7a7230582062c1c1804b2189cc96733b4ee99dd89d2b2961b020c6b2895e9eb5027bb3483f0029";


    //helloV1
    private static byte[] contractCodeV2 = ByteUtils.hexStringToBytes(contractCodeStringV2);

    /**
     * contract id
     */
    private static String testContractId = "CreditManager" + System.currentTimeMillis();

    /**
     * baas上创建的帐户名字
     */
    private static final String account = "mason0001";//

    private static final String account2 = "mason00012";//
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

    public static Identity deployContract(byte[] contractCode) {
        EVMParameter contractParameters = new EVMParameter();
        Identity identityByName = Utils.getIdentityByName(testContractId);
        DeployContractRequest request = new DeployContractRequest(userIdentity,
                identityByName, contractCode, VMTypeEnum.EVM,
                contractParameters, BigInteger.ZERO);
        TransactionReceiptResponse deployContractResult;
        deployContractResult = sdk.getContractService().deployContract(request);
        if (!deployContractResult.isSuccess()
                || deployContractResult.getTransactionReceipt().getResult() != 0) {
            exit("deployContract",
                    getErrorMsg((int) deployContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("deploy contract success.");
            System.out.println("deploy contract result: " + deployContractResult);
            return identityByName;
        }
        return null;
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
    private static void hello1() {
        EVMParameter parameters = new EVMParameter("hello()");

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
            exit("hello1", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("hello1 success.");
        }
    }

    private static void setInfo(Identity contractAddress) {
        //打印合约地址
        System.out.println("contract address: " + contractAddress);
        EVMParameter parameters = new EVMParameter("setAge(uint)");
//        parameters.addString("gushui030303");
        parameters.addUint(BigInteger.valueOf(100));
        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(userIdentity, contractAddress, parameters, BigInteger.ZERO, VMTypeEnum.EVM);
        TransactionReceiptResponse callContractResult;
        callContractResult = sdk.getContractService().callContract(request);
        //打印结果
        System.out.println("callContractResult: " + callContractResult.getTransactionReceipt());

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("info fail", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("info success.");
            TransactionReceipt transactionReceipt = callContractResult.getTransactionReceipt();
            System.out.println("info result: " + transactionReceipt);
            EVMOutput evmOutput = new EVMOutput(ByteUtils.toHexString(transactionReceipt.getOutput()));
            //按顺序获得返回值
            String name = evmOutput.getString();//get string
            BigInteger bigInteger = evmOutput.getUint(); // 100
            //打印结果
            System.out.println("string: " + name);
            System.out.println("bigInteger: " + bigInteger);
        }
    }

    private static void info(Identity contractAddress) {
        EVMParameter parameters = new EVMParameter("getInfo()");
        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(userIdentity,
                contractAddress, parameters, BigInteger.ZERO, VMTypeEnum.EVM);
        TransactionReceiptResponse callContractResult;
        callContractResult = sdk.getContractService().callContract(request);
        //打印结果
        System.out.println("callContractResult: " + callContractResult.getTransactionReceipt());

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("info fail", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("info success.");
            TransactionReceipt transactionReceipt = callContractResult.getTransactionReceipt();
            System.out.println("info result: " + transactionReceipt);
            EVMOutput evmOutput = new EVMOutput(ByteUtils.toHexString(transactionReceipt.getOutput()));
            //按顺序获得返回值
            String name = evmOutput.getString();//get string
            BigInteger bigInteger = evmOutput.getUint(); // 100
            //打印结果
            System.out.println("string: " + name);
            System.out.println("bigInteger: " + bigInteger);
        }
    }

    //InfoContract01
    private static void myinfo(Identity contractAddress) {
        EVMParameter parameters = new EVMParameter("testinfo()");
        CallContractRequest request = new CallContractRequest(userIdentity,
                contractAddress, parameters, BigInteger.ZERO, VMTypeEnum.EVM);
        TransactionReceiptResponse callContractResult;
        callContractResult = sdk.getContractService().callContract(request);
        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("info fail", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("info success.");
            TransactionReceipt transactionReceipt = callContractResult.getTransactionReceipt();
            EVMOutput evmOutput = new EVMOutput(ByteUtils.toHexString(transactionReceipt.getOutput()));
            String name = evmOutput.getString();//get string
            System.out.println("string: " + name);
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
    //创建账户 账户名称 公钥 恢复公钥

    /**
     * create testAccount1 success.返回信息:{"sequence":1,"trace_id":"","msg_name":"transaction_CreateAccount_Resp","msg_type":14,"return_code":0,"hash":"d8cd05198bfba2f17c8e2e1f2332391c29cf59a5a0822b7692b48a6af37c0a1a"}
     * @throws IOException
     */
    public static void createAccount() throws IOException {
        long startIndex = System.currentTimeMillis();
        String userPrivateKeyFile = "user.key";
        String testAccount1name = "account_1" + startIndex;
        //打印 account_11662366169892
        System.out.println("create testAccount1 start.返回信息:" + testAccount1name);
        Pkcs8KeyOperator pkcs8KeyOperator = new Pkcs8KeyOperator();
        userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(
                DemoSample.class.getClassLoader().getResourceAsStream(userPrivateKeyFile)),userPassword);
        //获取私钥  设置创建账户的名称
        // 创建账户 并设置参数。
        Account newAccount = new Account();
        newAccount.setIdentity(Utils.getIdentityByName(testAccount1name));
        newAccount.setBalance(BigInteger.valueOf(0));
        newAccount.setStatus(AccountStatus.NORMAL);

        AuthMap authMap1 = new AuthMap();//账户或合约的公钥与权重值
        newAccount.setAuthMap(authMap1.updateAuth(new PublicKey(userKeypair), 100));
        newAccount.setRecoverKey(new PublicKey(userKeypair));
        //创建账户
        CreateAccountRequest request = new CreateAccountRequest(userIdentity, newAccount);

        // create testAccount
        CreateAccountResponse createAccountResult = sdk.getAccountService().createAccount(request);
        if (!createAccountResult.isSuccess()) {
            exit("createAccount", getErrorMsg((int)createAccountResult.
                    getTransactionReceipt().getResult()));
        } else {
            System.out.println("create testAccount1 success.返回信息:"+createAccountResult.toString());
        }
    }

    //账户相关
    public static void listenAccount() throws IOException {

        IEventCallback handler = new IEventCallback() {

            public void onEvent(Message message) {
                PushAccountEvent accountEvent = (PushAccountEvent) message;
                //code
            }
        };

        // listen account
        BigInteger eventId = sdk.getEventService().listenAccount(Utils.getIdentityByName(account), handler, EventModelType.PUSH);

        if (eventId.longValue() == 0) {
            System.out.println("listen failed");
        } else {
            System.out.println("listen success");
        }
        if (sdk.getEventService().unListenAccount(eventId))
        {
            System.out.println("成功取消监听用户");
        }
    }
    //账户topics
    public static void listenTopics() throws IOException {

        IEventCallback handler = new IEventCallback() {
            public void onEvent(Message message) {
                PushTopicsEvent eventTopicsMessage = (PushTopicsEvent) message;
            }
        };
        // add contract
        List<String> topics = new ArrayList<String>();
        //系统合约，任意调用一个合约都会返回事件
        topics.add("积分发放");

        //EVM 合约，调用会触发合约内部 IssueEvent 事件的方法
        IHash hashTool = HashFactory.getHash();
        byte[] sha256 = hashTool.hash("IssueEvent(identity,int256)".getBytes());
        topics.add(ByteUtils.toHexString(sha256));

        // listen topics
        BigInteger result = sdk.getEventService().listenTopics(topics, handler,
                VMTypeEnum.EVM, EventModelType.PUSH);

        //调用 EVM 的合约，将触发两个 topic，一个 call_contract 的事件，一个TEST 的事件
        EVMParameter parameters = new EVMParameter("test(identity,uint256)");
        parameters.addIdentity(Utils.getIdentityByName(account));
        parameters.addUint(BigInteger.valueOf(50));
        CallContractRequest request = new CallContractRequest(Utils.getIdentityByName(account),
                Utils.getIdentityByName(testContractId), parameters, BigInteger.ZERO, VMTypeEnum.EVM);
        System.out.println("订阅主题的错误码: "+sdk.getContractService().callContract(request).getErrorCode());
        if(result.longValue() == 0){
            System.out.println("listen failed");
        }else {
            System.out.println("listen success");
        }

        //结束后取消订阅主题
        if(sdk.getEventService().unListenTopics(result)){
            System.out.println("成功取消订阅主题");
        };

    }

    //节点状态
    public static void queryNodeMetricsStatus() throws IOException {
        long startTime = System.currentTimeMillis()-10;
        long endTime = System.currentTimeMillis();
        QueryNodeMetricsStatusResponse result = sdk.getQueryService().
                queryNodeMetricsStatus( startTime, endTime);
        System.out.println(result.getInfo());
    }


    public static void main(String[] args) throws Exception {
        //step 1:init mychain env.
        initMychainEnv();

//        //step 2: init sdk client
        initSdk();
//
//        //step 3 : deploy a contract using useridentity.
      //  deployContract(contractCode);

        //step 4 : 升级合约
//        upgradeContract(contractCode1);


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


        //testContract
        testContract();
//
//
//        getIdentityName();

//        hello(Utils.getIdentityByName("CreditManager1662379887264"));

        sdk.shutDown();
    }

    private static void deployContractAndCall() {


    }

    public static void testContract() {
        //部署合约 并且调用合约 返回合约名称
//        Identity identity = deployContract(contractCode1);
////        //打印合约地址 11652956c69fcc29e3922363073d5daa24eeec4613c1452b607589da95cd8892
//        System.out.println("合约地址:"+identity.toString());
////        //打印testContractId
//        System.out.println("testContractId:"+testContractId);

        Identity identity = Utils.getIdentityByName("CreditManager1662461289480");

//        合约地址:3d2590198e8c5fd347346626686d6be8c4e8a60a8ad0d5ef5441ea461095d369
//        testContractId:CreditManager1662461289480

        //setvalue合约
        Identity identity1=new Identity("0x3d2590198e8c5fd347346626686d6be8c4e8a60a8ad0d5ef5441ea461095d369");
//        setInfo(identity1);
//        //调用合约
        info(identity);
    }
    public static void testUpdateContract() throws IOException {
       // upgradeContract(contractCodeV2,newidentity);
    }



    private static void upgradeContract(byte[] code,Identity myIdentity) {
//        String newContractCode = "";
//        byte[] code = ByteUtils.hexStringToBytes(newContractCode);
        UpdateContractRequest request = new UpdateContractRequest(myIdentity
                , code, VMTypeEnum.EVM);
        // 请参考错误信息章节，检查返回的数据
        UpdateContractResponse response = sdk.getContractService().updateContract(request);
        if (!response.isSuccess()) {
            exit("upgradeContract", getErrorMsg((int)response.
                    getTransactionReceipt().getResult()));
        } else {
            System.out.println("upgradeContract success.返回信息:"+response.toString());
            // 交易hash
            System.out.println("upgradeContract success.交易hash:"+response.getTxHash());
            // 合约地址
            System.out.println("upgradeContract success.合约地址:"+response.getTransactionReceipt().getResult());
        }
    }


    //from 4f976466d7c6a45e6cd6a71194dd7b4b04b0dd3c517eea205ce1435cf02918b9 部署合约账户
    private static void getIdentityName() {
//        mason0001:++++++++++++++++4f976466d7c6a45e6cd6a71194dd7b4b04b0dd3c517eea205ce1435cf02918b9
//        mason0002:++++++++++++++++0cb05c88eee707835c8cc2be9599713c1d96f84c6a62f180cbea7bd96e50619f
//        masonDemo:++++++++++++++++b74c38937c1574cf1aa151767d34d5dd68977cff26b82303e881890062ab9d2c
//        manager:++++++++++++++++fd63d67db27e7dcb52771defc00ef704fe2221143ced18e88babc6cf81693a73
//        userIdentity:++++++++++++++++4f976466d7c6a45e6cd6a71194dd7b4b04b0dd3c517eea205ce1435cf02918b9

        //获取账户名  userIdentity = Utils.getIdentityByName(account); /
        Identity mason0001 = Utils.getIdentityByName("mason0001");
        Identity mason0002 = Utils.getIdentityByName("mason0002");
        Identity masonDemo = Utils.getIdentityByName("masonDemo");
        //打印账户名 mason0001 mason0002
        System.out.println("mason0001:++++++++++++++++" + mason0001);
        System.out.println("mason0002:++++++++++++++++" + mason0002);
        System.out.println("masonDemo:++++++++++++++++" + masonDemo);

        //CreditManager1662370594411
        Identity manager = Utils.getIdentityByName("CreditManager1662370594411");
        System.out.println("manager:++++++++++++++++" + manager);

        //get user identity
        userIdentity = Utils.getIdentityByName(account);
        System.out.println("userIdentity:++++++++++++++++" + userIdentity);

        //CreditManager1662379887263
        userIdentity = Utils.getIdentityByName("CreditManager1662379887264");
    }
}




