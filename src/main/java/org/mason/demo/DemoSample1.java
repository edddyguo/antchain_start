package org.mason.demo;

import com.alipay.mychain.sdk.api.MychainClient;
import com.alipay.mychain.sdk.api.callback.IAsyncCallback;
import com.alipay.mychain.sdk.api.callback.IEventCallback;
import com.alipay.mychain.sdk.api.env.ClientEnv;
import com.alipay.mychain.sdk.api.env.ISslOption;
import com.alipay.mychain.sdk.api.env.SignerOption;
import com.alipay.mychain.sdk.api.env.SslBytesOption;
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
import com.alipay.mychain.sdk.domain.event.EventModelType;
import com.alipay.mychain.sdk.domain.transaction.Transaction;
import com.alipay.mychain.sdk.domain.transaction.TransactionReceipt;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.Message;
import com.alipay.mychain.sdk.message.Response;
import com.alipay.mychain.sdk.message.event.PushAccountEvent;
import com.alipay.mychain.sdk.message.event.PushTopicsEvent;
import com.alipay.mychain.sdk.message.query.QueryTransactionResponse;
import com.alipay.mychain.sdk.message.status.QueryNodeMetricsStatusResponse;
import com.alipay.mychain.sdk.message.transaction.AbstractTransactionRequest;
import com.alipay.mychain.sdk.message.transaction.TransactionReceiptResponse;
import com.alipay.mychain.sdk.message.transaction.account.CreateAccountRequest;
import com.alipay.mychain.sdk.message.transaction.account.CreateAccountResponse;
import com.alipay.mychain.sdk.message.transaction.confidential.ConfidentialRequest;
import com.alipay.mychain.sdk.message.transaction.contract.*;
import com.alipay.mychain.sdk.type.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.utils.ByteUtils;
import com.alipay.mychain.sdk.utils.IOUtil;
import com.alipay.mychain.sdk.utils.RandomUtil;
import com.alipay.mychain.sdk.vm.EVMOutput;
import com.alipay.mychain.sdk.vm.EVMParameter;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

public class DemoSample1 {
    private static final String contractCodeString1 = "0x608060405234801561001057600080fd5b506102c8806100206000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635a9b0b8914610051578063b6b9af73146100e8575b600080fd5b34801561005d57600080fd5b5061006661012d565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156100ac578082015181840152602081019050610091565b50505050905090810190601f1680156100d95780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b3480156100f457600080fd5b5061012b600480360381019080803590602001908201803590602001919091929391929390803590602001909291905050506101d9565b005b6060600080600154818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101ca5780601f1061019f576101008083540402835291602001916101ca565b820191906000526020600020905b8154815290600101906020018083116101ad57829003601f168201915b50505050509150915091509091565b8282600091906101ea9291906101f7565b5080600181905550505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061023857803560ff1916838001178555610266565b82800160010185558215610266579182015b8281111561026557823582559160200191906001019061024a565b5b5090506102739190610277565b5090565b61029991905b8082111561029557600081600090555060010161027d565b5090565b905600a165627a7a72305820fc73fb32e1317b10ec1b5b566faf2a90342e3759e7ff5f5e3d2d175f340a55780029";
    private static byte[] contractCode1 = ByteUtils.hexStringToBytes(contractCodeString1);
    private static final String contractCodeStringV2 = "0x608060405234801561001057600080fd5b5061065a806100206000396000f300608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635a9b0b89146100675780638262963b146100fe57806385b31d7b14610171578063b1899c4114610208575b600080fd5b34801561007357600080fd5b5061007c61029f565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156100c25780820151818401526020810190506100a7565b50505050905090810190601f1680156100ef5780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b34801561010a57600080fd5b5061016f600480360381019080803590602001908201803590602001908080601f01602080910402602001604051908101604052809392919081815260200183838082843782019150505050505091929192908035906020019092919050505061034b565b005b34801561017d57600080fd5b50610186610431565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b838110156101cc5780820151818401526020810190506101b1565b50505050905090810190601f1680156101f95780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b34801561021457600080fd5b5061021d6104dd565b6040518080602001838152602001828103825284818151815260200191508051906020019080838360005b83811015610263578082015181840152602081019050610248565b50505050905090810190601f1680156102905780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b6060600080600154818054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561033c5780601f106103115761010080835404028352916020019161033c565b820191906000526020600020905b81548152906001019060200180831161031f57829003601f168201915b50505050509150915091509091565b8160009080519060200190610361929190610589565b50806001819055507f010becc10ca1475887c4ec429def1ccc2e9ea1713fe8b0d4e9a1d009042f6b8e6000600154604051808060200183815260200182810382528481815460018160011615610100020316600290048152602001915080546001816001161561010002031660029004801561041e5780601f106103f35761010080835404028352916020019161041e565b820191906000526020600020905b81548152906001019060200180831161040157829003601f168201915b5050935050505060405180910390a15050565b6060600080600154818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156104ce5780601f106104a3576101008083540402835291602001916104ce565b820191906000526020600020905b8154815290600101906020018083116104b157829003601f168201915b50505050509150915091509091565b6060600080600154818054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561057a5780601f1061054f5761010080835404028352916020019161057a565b820191906000526020600020905b81548152906001019060200180831161055d57829003601f168201915b50505050509150915091509091565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106105ca57805160ff19168380011785556105f8565b828001600101855582156105f8579182015b828111156105f75782518255916020019190600101906105dc565b5b5090506106059190610609565b5090565b61062b91905b8082111561062757600081600090555060010161060f565b5090565b905600a165627a7a7230582062c1c1804b2189cc96733b4ee99dd89d2b2961b020c6b2895e9eb5027bb3483f0029";
    private static byte[] contractCodeV2 = ByteUtils.hexStringToBytes(contractCodeStringV2);
    private static String testContractId = "CreditManager" + System.currentTimeMillis();
    private static final String account = "mason0001";//
    private static final String account2 = "mason00012";//
    private static Identity userIdentity;
    private static Keypair userKeypair;
    private static Identity testAccount1 = Utils.getIdentityByName("test_account_" + System.currentTimeMillis());
    private static MychainClient sdk;
    private static String keyPassword = "Zhxc6545398@";  //根据实际情况更新，申请证书时候指定的SSL密码
    private static String userPassword = "Zhxc6545398@"; //根据实际情况更新。申请证书时，创建账户的密码
    private static String host = "47.103.163.48"; //根据实际情况更新，在BaaS平台，通过查看目标合约链"详情"，在"区块浏览器"中查看"节点详情"可获取链节点的 IP地址 和 端口号。
    private static int port = 18130;               //根据实际情况更新
    private static String trustStorePassword = "mychain";
    private static ClientEnv env;
    private static boolean isTeeChain = false;
    private static List<byte[]> publicKeys = new ArrayList<byte[]>();
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
        userKeypair = pkcs8KeyOperator.load(IOUtil.inputStreamToByte(DemoSample1.class.getClassLoader().getResourceAsStream(userPrivateKeyFile)), userPassword);

        // use publicKeys by tee
        if (isTeeChain) {
            Keypair keypair = new Pkcs8KeyOperator()
                    .loadPubkey(
                            IOUtil.inputStreamToByte(DemoSample1.class.getClassLoader().getResourceAsStream("test_seal_pubkey.pem")));
            byte[] publicKeyDer = keypair.getPubkeyEncoded(); //tee_rsa_public_key.pem 从BaaS下载获取
            publicKeys.add(publicKeyDer);
        }
        env = buildMychainEnv();
        ILogger logger = AbstractLoggerFactory.getInstance(DemoSample1.class);
        env.setLogger(logger);
    }

    private static ClientEnv buildMychainEnv() throws IOException {
        InetSocketAddress inetSocketAddress = InetSocketAddress.createUnresolved(host, port);
        String keyFilePath = "client.key";
        String certFilePath = "client.crt";
        String trustStoreFilePath = "trustCa";

        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(IOUtil.inputStreamToByte(DemoSample1.class.getClassLoader().getResourceAsStream(keyFilePath)))
                .certBytes(IOUtil.inputStreamToByte(DemoSample1.class.getClassLoader().getResourceAsStream(certFilePath)))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        IOUtil.inputStreamToByte(DemoSample1.class.getClassLoader().getResourceAsStream(trustStoreFilePath)))
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

    private static void initSdk() {
        sdk = new MychainClient();
        boolean initResult = sdk.init(env);
        if (!initResult) {
            exit("initSdk", "sdk init failed.");
        }
    }

    public static void main(String[] args) throws Exception {
        initMychainEnv();
        initSdk();
        testContract();
        sdk.shutDown();
    }
    public static void testContract() {
//        Identity identity = deployContract(contractCode1);
        Identity identity1 = new Identity("0x3a8bc06d367af39028eb140fd79267f153613faba9720d209e6c73b51be250ee");
//        System.out.println("identity: " + identity);
//        System.out.println("account: " + testContractId);
//        callSetInfo(identity1);

//        asyncCallContract();
        callContract(identity1);
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

    private static void upgradeContract(byte[] code, Identity myIdentity) {
//        String newContractCode = "";
//        byte[] code = ByteUtils.hexStringToBytes(newContractCode);
        UpdateContractRequest request = new UpdateContractRequest(myIdentity
                , code, VMTypeEnum.EVM);
        // 请参考错误信息章节，检查返回的数据
        UpdateContractResponse response = sdk.getContractService().updateContract(request);
        if (!response.isSuccess()) {
            exit("upgradeContract", getErrorMsg((int) response.
                    getTransactionReceipt().getResult()));
        } else {
            System.out.println("upgradeContract success.返回信息:" + response.toString());
            // 交易hash
            System.out.println("upgradeContract success.交易hash:" + response.getTxHash());
            // 合约地址
            System.out.println("upgradeContract success.合约地址:" + response.getTransactionReceipt().getResult());
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

    //callContract success.返回信息:{"sequence":1,"trace_id":"","msg_name":"transaction_CallContract_Resp","msg_type":21,"return_code":0,"hash":"b00b7d22e928dffe6e48b7ecfbd9acab9d6226bd5e9d6f628e4d2a5c4eed2eae"}
    public static void callContract(Identity identity) {
        EVMParameter parameters = new EVMParameter("setname(string)");
//        parameters.addIdentity(identity);
//        parameters.addUint(BigInteger.valueOf(100));
        parameters.addString("hello mason! ");
        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(userIdentity, identity, parameters, BigInteger.ZERO, VMTypeEnum.EVM);

        CallContractResponse callContractResponse = sdk.getContractService().callContract(request);
        if (!callContractResponse.isSuccess()) {
            System.out.println("callContract1 fail.返回信息:" + callContractResponse.toString());
        } else {
            // 交易收据
            TransactionReceipt transactionReceipt = callContractResponse.getTransactionReceipt();
            if (transactionReceipt.getResult() != 0) {
                System.out.println("callContract2 fail.返回信息:" + callContractResponse.toString());
            } else {
                // 手动抛出的错误可在evmOutput中查看
                EVMOutput evmOutput = new EVMOutput(Hex.toHexString(transactionReceipt.getOutput()));
                //获取要解析的类型
//                BigInteger uint = evmOutput.getUint();
                System.out.println("callContract success.返回信息:" + callContractResponse.toString());
            }
        }
    }

    public static void asyncCallContract() {
        String contractName = "Hello001";
        String accountName = account;
        EVMParameter parameters = new EVMParameter("setname()");
        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(Utils.getIdentityByName(accountName), Utils.getIdentityByName(contractName), parameters, BigInteger.ZERO, VMTypeEnum.EVM);
        int result = sdk.getContractService().asyncCallContract(request, new IAsyncCallback() {
            @Override
            public void onResponse(int errorCode, Response response) {
                // 请参考错误信息章节，检查返回的数据
                CallContractResponse callContractResponse = (CallContractResponse) response;
                if (!callContractResponse.isSuccess()) {
                    System.out.println("callContract1 fail.返回信息:" + callContractResponse.toString());
                } else {
                    // 交易收据
                    TransactionReceipt transactionReceipt = callContractResponse.getTransactionReceipt();
                    if (transactionReceipt.getResult() != 0) {
                        System.out.println("callContract2 fail.返回信息:" + callContractResponse.toString());
                    } else {
                        // 手动抛出的错误可在evmOutput中查看
                        EVMOutput evmOutput = new EVMOutput(Hex.toHexString(transactionReceipt.getOutput()));
                        //获取要解析的类型
                        System.out.println("callContract2 fail.返回信息:" + evmOutput.getString());
                    }
                }
            }
        });
    }


    private static void callSetInfo(Identity identity) {
        EVMParameter parameters = new EVMParameter("Info(string name,uint age)");
        parameters.addString("test");
        parameters.addUint(BigInteger.valueOf(100));

        // build CallContractRequest
        CallContractRequest request = new CallContractRequest(userIdentity,
                identity, parameters, BigInteger.ZERO, VMTypeEnum.EVM);

        TransactionReceiptResponse callContractResult;
        callContractResult = sdk.getContractService().callContract(request);

        if (!callContractResult.isSuccess() || callContractResult.getTransactionReceipt().getResult() != 0) {
            exit("issue", getErrorMsg((int) callContractResult.getTransactionReceipt().getResult()));
        } else {
            System.out.println("issue success.");
        }
    }

}