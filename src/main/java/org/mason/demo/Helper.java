package org.mason.demo;

import com.alipay.mychain.sdk.api.utils.Utils;
import com.alipay.mychain.sdk.domain.transaction.TransactionReceipt;
import com.alipay.mychain.sdk.errorcode.ErrorCode;
import com.alipay.mychain.sdk.message.transaction.account.TransferBalanceRequest;
import com.alipay.mychain.sdk.message.transaction.account.TransferBalanceResponse;

import java.math.BigInteger;

import org.apache.log4j.Logger;
public class Helper {
    private static final Logger logger = Logger.getLogger(Helper.class);
    //define test function
    public void test(){
        //打印
        /**
         * static修饰的方法或者变量是属于类的，所有类的对象共享的。当在类加载的过程中，static修饰的方法或变量已经被加载到方法区中了，如果此时你去调用对象的话，会报错。
         *         Helper a=new Helper();
         *         a.test();
        */

        System.out.println("Hello World++++++++++++++++++");
    }
}
