pragma solidity ^0.4.23;

// pragma experimental ABIEncoderV2;

interface tokenInterface {
    function balanceOf(identity owner) external view returns (uint256);
    function transfer(identity to, uint256 value) external returns (bool) ;
    function allowance(identity owner, identity spender) external view returns (uint256) ;
    function issue(identity account, uint256 value) external returns (bool) ;
    function transferFrom(identity from, identity to, uint256 value) external returns (bool) ;
    function _transfer(identity from, identity to, uint256 value) external;
    function approve(identity spender, uint256 value) public returns (bool);
}

contract BizContract {
    identity admin;
    tokenInterface mytoken ;
    constructor(identity scoreaddress) public {
        mytoken = tokenInterface(scoreaddress);
        admin = msg.sender;
    }
    //授权
    function testApprove(identity spender, uint256 value) public returns(bool){
        (bool success)=mytoken.approve(spender,value);
        return success;
    }

    function testtransferFrom(identity from,identity to,uint256 amount) public returns(bool){
        // 1. 跨合约调用，需要通过合约 API 定义及合约 ID 生成一个合约对象
        (bool success)=mytoken.transferFrom(from,to,amount);
        // (bool success)=tokenInterface(scoreaddress).call(abi.encodeWithSignature("_transfer(identity,identity,uint256)", "call _transfer", from,to,10000));
        return success;
    }

    //transfer
    function test_transfer(identity from,identity to,uint256 amount) public{
        // 1. 跨合约调用，需要通过合约 API 定义及合约 ID 生成一个合约对象
        mytoken._transfer(from,to,amount);
    }

    //test_transfer
    function testTransfer(identity to,uint256 amount) public{
        // 1. 跨合约调用，需要通过合约 API 定义及合约 ID 生成一个合约对象
        mytoken.transfer(to,amount);
    }

    //issue
    function testissue(identity from,uint256 amount)public returns(bool){
        (bool success)=mytoken.issue(from,amount);
        return success;
    }

    //balance
    function testBalance(identity from)public returns(uint256){
        uint256 balance=mytoken.balanceOf(from);
        return balance;
    }
}