 pragma solidity ^0.6.4;
 pragma experimental ABIEncoderV2;


 interface OracleInterface {

     function curlRequestDefault(bytes32 _biz_id, string _curl_cmd, bool _if_callback, identity _callback_identity, uint256 _delay_time) external returns (bytes32);

     function oracleCallbackCurlResponse (bytes32 _request_id, bytes32 _biz_id, uint32 _error_code, uint32 _resp_status, bytes _resp_header, bytes _resp_body, identity _call_identity) external returns (bool);

 }

 // 实现一个 demo 合约
 contract BizContract {

     // 业务 ID 与预言机请求 ID 的关联关系
     mapping(bytes32 => bytes32) requests;

     // 调用预言机合约的 CURL 接口
     function rawCURLRequest(identity oracle_address, bytes32 biz_id, string cmd) public{
         // 1. 跨合约调用，需要通过合约 API 定义及合约 ID 生成一个合约对象
         OracleInterface oracle = OracleInterface(oracle_address);

         //
         // 2. 发送 CURL 请求
         //   （例如查询股票行情信息，cmd 参数的值可以是“https://hq.sinajs.cn/list=hk00941”）
          bytes32 request_id = oracle.curlRequestDefault(biz_id, cmd, true, this, 0);
           // 3. 记录预言机返回的 request id
          requests[biz_id] = request_id;

         // 4. 请求阶段结束，等待回调
         return;
     }

     // 业务合约用于接收预言机合约的 CURL 请求结果回调
     function oracleCallbackCurlResponse (bytes32 _request_id, bytes32 _biz_id, uint32 _error_code, uint32 _resp_status, bytes _resp_header, bytes _resp_body, identity _call_identity) external returns (bool){
         // 业务处理回调结果
         return true;
     }
 }
